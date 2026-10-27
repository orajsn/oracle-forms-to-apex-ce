"""Internal OPAF handoff. No direct LLM calls and no inferred release success."""
from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import ssl
import tempfile
import zipfile
from http.cookies import SimpleCookie
from pathlib import Path
from datetime import datetime,timezone
from urllib.parse import urlsplit

from .intake import checked_source, inventory, MAX_CONVERSION_BYTES

WORKFLOW_ID = '573360A075206A99E0637D59000A704E'
CERT_SHA256 = '68be4eeb6c362a46c0f1cb8bc4eda4585772a8f8a778dbace28cb60992830f93'
MAX_SOURCE_BYTES = MAX_CONVERSION_BYTES
_NO_FRESH_PROJECTION = object()


class OpafError(RuntimeError):
    def __init__(self,message,status_code=None):
        super().__init__(message)
        self.status_code=status_code


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def _utc_now():
    return datetime.now(timezone.utc)


def _environment_fields(value, target_profile, role_name, request):
    """Compare observed public metadata only; no model execution is implied."""
    opaf = target_profile['opaf']
    role = opaf['roles'][role_name]
    expected = {
        'schema_version':1, 'scope':'opaf-model-environment-v1',
        'trust_boundary':'authenticated_fox_executor_not_vendor_attestation',
        'job_id':request['job_id'], 'role':role_name,
        'source_manifest_sha256':request['source_hash'],
        'target_profile_sha256':canonical_hash(target_profile),
        'observed_at_utc':value['observed_at_utc'],
        'opaf':{key:opaf[key] for key in ('base_url','certificate_sha256','model_authentication','version_number','build_id')},
        'workflow':{**role,'published':True}, 'opaf_version':target_profile['tested_versions']['opaf'],
    }
    if role_name not in {'mapper','reviewer'} or canonical_hash(value)!=canonical_hash(expected):
        raise ValueError()
    return role


def validate_model_environment(value, target_profile, role_name, request, invocation):
    """Pure historical binding check; never checks today's clock or contacts OPAF."""
    try:
        role = _environment_fields(value,target_profile,role_name,request)
        def utc(text):
            if not isinstance(text,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)',text):
                raise ValueError()
            return datetime.fromisoformat(text.replace('Z','+00:00'))
        started, completed = utc(invocation['started_at_utc']), utc(invocation['completed_at_utc'])
        lead = (started - utc(value['observed_at_utc'])).total_seconds()
        if completed < started or not -5 <= lead <= 120:
            raise ValueError()
        if any(invocation.get(key)!=role[key] for key in ('workflow_id','model','graph_sha256')):
            raise ValueError()
    except (KeyError,ValueError,TypeError,AttributeError,OverflowError):
        raise OpafError('Model environment evidence does not match its historical invocation.') from None
    return value


def load_native_profile(path):
    value=json.loads(Path(path).read_text(encoding='utf-8'))
    if set(value)!={'schema_version','profile_id','opaf_base_url','certificate_sha256','mapper','reviewer'} or value['schema_version']!=1 or value['profile_id']!='native-table-form-v1':
        raise OpafError('Unsupported native deployment profile.')
    for role in ('mapper','reviewer'):
        item=value[role]
        if not isinstance(item,dict) or set(item)!={'workflow_id','model','graph_sha256'}:
            raise OpafError('Native role configuration is incomplete.')
        if not re.fullmatch(r'[A-Fa-f0-9]{16,64}',item['workflow_id']) or not re.fullmatch(r'[a-f0-9]{64}',item['graph_sha256']) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',item['model']):
            raise OpafError('Native role configuration is invalid.')
    if value['mapper']['workflow_id'].upper()==value['reviewer']['workflow_id'].upper():
        raise OpafError('Mapper and reviewer must be separate workflows.')
    # Validate origin and certificate before any credential is loaded/sent.
    OpafClient(value['opaf_base_url'],'','',value['certificate_sha256'])
    return value


class OpafClient:
    def __init__(self, base_url: str, username: str, password: str, certificate_sha256: str = CERT_SHA256):
        url = urlsplit(base_url)
        if url.scheme != 'https' or url.username or url.password or url.query or url.fragment or url.path.rstrip('/') != '/agentFactory':
            raise ValueError('An HTTPS Agent Factory base URL is required.')
        if not re.fullmatch(r'[0-9a-f]{64}', certificate_sha256):
            raise ValueError('A pinned certificate SHA-256 is required.')
        self.host, self.port = url.hostname, url.port or 443
        self.origin = f'https://{url.netloc}'
        self.username, self.password = username, password
        self.pin = certificate_sha256
        self.cookie = None

    def _request(self, method, path, payload=None, login=False):
        # The self-signed OPAF certificate is accepted only after exact pin matching.
        conn = http.client.HTTPSConnection(self.host, self.port, context=ssl._create_unverified_context(), timeout=600)
        try:
            conn.connect()
            if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != self.pin:
                raise OpafError('OPAF TLS identity changed; connection blocked.')
            headers = {'Accept':'application/json'}
            if login:
                basic = base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
                headers['Authorization'] = 'Basic ' + basic
            else:
                headers.update(Cookie=self.cookie, Origin=self.origin, Referer=self.origin+'/agentFactory/', **{'Content-Type':'application/json'})
            conn.request(method, '/agentFactory'+path, json.dumps(payload) if payload is not None else None, headers)
            response = conn.getresponse()
            raw = response.read(8_000_001)
            if response.status != 200 or len(raw) > 8_000_000:
                raise OpafError(f'OPAF request did not complete (HTTP {response.status}). No automatic retry was attempted.')
            if login:
                cookies = SimpleCookie()
                for key,value in response.getheaders():
                    if key.lower() == 'set-cookie': cookies.load(value)
                if 'agent_factory_session' not in cookies:
                    raise OpafError('OPAF did not establish an authenticated session.')
                self.cookie = 'agent_factory_session='+cookies['agent_factory_session'].value
            try: return json.loads(raw)
            except ValueError: raise OpafError('OPAF returned an unsupported response format.') from None
        finally:
            conn.close()

    def run(self, job_id):
        if not re.fullmatch(r'fox-[a-f0-9]{20}', job_id): raise ValueError('Invalid FOX run ID.')
        try:
            self._request('GET', '/v1/loginValidation', login=True)
            return self._request('POST', '/v1/agentBuilder/run/'+WORKFLOW_ID,
                                 {'message':json.dumps({'job_id':job_id})})
        except (OSError, http.client.HTTPException) as exc:
            raise OpafError('OPAF transport failed. Reconcile the existing run before retrying.') from None

    def invoke(self,role,request):
        """Run a pinned tool-free OPAF role and record executor-observed evidence.

        Hashes cover canonical JSON objects, not HTTP credentials or vendor signatures.
        No automatic retry is performed after transport uncertainty.
        """
        output, invocation, _ = self._invoke(role, request)
        return output, invocation

    def invoke_with_environment(self, role, request, *, role_name, target_profile):
        """Observe actual version/graph/saved OCI model before one new invocation.

        The only persisted configuration values are whitelisted public metadata.
        Saved configurations can contain secrets and must never enter evidence,
        exception messages or logs. Completed checkpoints need no live OPAF.
        """
        return self._invoke(role,request,role_name=role_name,target_profile=target_profile)

    def observe_environment(self, role, request, *, role_name, target_profile):
        """GET-only authenticated version/graph/saved-LLM observation.

        No invocation, inference, reviewer approval or execution receipt is
        created. Health callers must label this as an environment observation,
        never reuse it as proof that a model ran. Source text is not transmitted.
        Only whitelisted non-secret metadata leaves this method.
        """
        try:
            workflow_id=role['workflow_id']
            if not re.fullmatch(r'[A-Fa-f0-9]{16,64}',workflow_id):raise ValueError()
            if (not re.fullmatch(r'fox-[a-f0-9]{20}',request['job_id'])
                    or not re.fullmatch(r'[a-f0-9]{64}',request['source_hash'])):raise ValueError()
            expected=target_profile['opaf']
            if (role_name not in {'mapper','reviewer'} or expected['roles'][role_name]!=role
                    or expected['base_url']!=self.origin+'/agentFactory'
                    or expected['certificate_sha256']!=self.pin):
                raise OpafError('Model target profile differs from the configured OPAF client.')
            self._request('GET','/v1/loginValidation',login=True)
            observed_at=_utc_now()
            version=self._request('GET','/v1/version')
            current=self._request('GET','/v1/agents/'+workflow_id)['data']
            if not current.get('published') or canonical_hash(current['data'])!=role['graph_sha256']:
                raise OpafError('OPAF workflow changed or is unpublished; revalidate its deployment profile.')
            # Schema observed from authenticated OPAF26.4 APIs, not inferred
            # from the expected role. Follow the actual graph's selection.
            nodes=current['data']['nodes']
            if len(nodes)!=4 or sorted(node['data']['type'] for node in nodes)!=sorted(
                    ['chatInputComponent','promptComponent','llmStep','chatOutputComponent']):
                raise OpafError('The native OPAF graph must remain tool-free.')
            selected=next(node['data']['template']['llmToUse']['value'] for node in nodes if node['data']['type']=='llmStep')
            rows=self._request('GET','/v1/getSavedLLMConfigurations')['data']['savedConfiguration']
            if not isinstance(rows,list):raise ValueError()
            matching=[row for row in rows if isinstance(row,dict) and row.get('name')==selected]
            if len(matching)!=1:raise ValueError()
            saved=matching[0];details=saved['connectionDetails']
            if (saved.get('provider')!='oci' or saved.get('isActive')!='Y'
                    or details.get('credentials_type')!='INSTANCE_PRINCIPAL'
                    or details.get('compartment_id')!=target_profile['oci']['compartment_id']
                    or details.get('service_endpoint')!='https://inference.generativeai.'+target_profile['oci']['region']+'.oci.oraclecloud.com'):
                raise OpafError('Selected model connection does not match the approved OCI processing path.')
            published=current['published']
            if not (published is True or type(published) is int and published==1):raise ValueError()
            environment={
                'schema_version':1,'scope':'opaf-model-environment-v1',
                'trust_boundary':'authenticated_fox_executor_not_vendor_attestation',
                'job_id':request['job_id'],'role':role_name,
                'source_manifest_sha256':request['source_hash'],
                'target_profile_sha256':canonical_hash(target_profile),'observed_at_utc':observed_at.isoformat(),
                'opaf':{'base_url':self.origin+'/agentFactory','certificate_sha256':self.pin,
                        'model_authentication':'oci_instance_principal',
                        'version_number':version['VERSION_NUMBER'],'build_id':version['BUILD_ID']},
                'workflow':{'workflow_id':workflow_id,'model':details['model_id'],
                            'graph_sha256':canonical_hash(current['data']),'published':True},
                'opaf_version':version['VERSION_STRING'],
            }
            _environment_fields(environment,target_profile,role_name,request)
            return environment
        except (KeyError,ValueError,TypeError,AttributeError,StopIteration,OSError,http.client.HTTPException):
            raise OpafError('Read-only OPAF environment observation failed or returned an invalid result.') from None

    def _invoke(self,role,request,*,role_name=None,target_profile=None):
        workflow_id=role['workflow_id']
        if not re.fullmatch(r'[A-Fa-f0-9]{16,64}',workflow_id):
            raise OpafError('Invalid native workflow identity.')
        encoded=json.dumps(request,ensure_ascii=False,allow_nan=False)
        if len(encoded.encode())>650_000:raise OpafError('Native model request exceeds the configured bound.')
        try:
            environment=None
            if target_profile is not None:
                environment=self.observe_environment(role,request,role_name=role_name,target_profile=target_profile)
            else:
                self._request('GET','/v1/loginValidation',login=True)
                current=self._request('GET','/v1/agents/'+workflow_id)['data']
                if not current.get('published') or canonical_hash(current['data'])!=role['graph_sha256']:
                    raise OpafError('OPAF workflow changed or is unpublished; revalidate its deployment profile.')
            started=_utc_now().isoformat()
            if environment is not None:
                validate_model_environment(environment,target_profile,role_name,request,
                    {**role,'started_at_utc':started,'completed_at_utc':started})
            response=self._request('POST','/v1/agentBuilder/run/'+workflow_id,{'message':encoded})
            completed=_utc_now().isoformat()
            message=response.get('message')
            if isinstance(message,str):message=json.loads(message)
            if not isinstance(message,dict) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',response.get('roomId','')):
                raise OpafError('OPAF did not return structured output with an invocation identity.')
            invocation={'workflow_id':workflow_id,'room_id':response['roomId'],'model':role['model'],
                        'graph_sha256':role['graph_sha256'],'request_sha256':canonical_hash(request),
                        'response_sha256':canonical_hash(response),'started_at_utc':started,'completed_at_utc':completed}
            if environment is not None:
                validate_model_environment(environment,target_profile,role_name,request,invocation)
            return message,invocation,environment
        except (KeyError,ValueError,TypeError,AttributeError,StopIteration,OSError,http.client.HTTPException):
            raise OpafError('Native OPAF invocation failed or returned an invalid result; no automatic retry.') from None


def stage_job(job: Path, shared_root: Path) -> Path:
    if job.is_symlink() or not re.fullmatch(r'fox-[a-f0-9]{20}', job.name):
        raise ValueError('Invalid FOX job directory.')
    snapshot = json.loads((job/'source-snapshot.json').read_text(encoding='utf-8'))
    files = snapshot.get('files', [])
    if not files or sum(len(f['text'].encode('utf-8')) for f in files) > MAX_SOURCE_BYTES:
        raise ValueError('Use a nonempty source package under the 300 KB MVP conversion limit.')
    raw_files=[]
    for f in files:
        raw=f['text'].encode('utf-8')
        if hashlib.sha256(raw).hexdigest()!=f['sha256'] and hashlib.sha256(b'\xef\xbb\xbf'+raw).hexdigest()==f['sha256']:
            raw=b'\xef\xbb\xbf'+raw
        raw_files.append(raw)
    checked = [checked_source(f['name'], raw) for f,raw in zip(files,raw_files)]
    if len({f['name'] for f in checked}) != len(checked): raise ValueError('Duplicate source names.')
    for original, current in zip(files, checked):
        if original['sha256'] != current['sha256']: raise ValueError('Source file changed after approval.')
    inv = inventory(checked)
    if inv['source_hash'] != snapshot['source_hash'] or inv['missing_count'] or not inv['conversion_eligible']:
        raise ValueError('Source manifest changed, dependencies remain unresolved, or source assessment blocks conversion.')
    shared_root = shared_root.resolve(strict=True)
    target = shared_root/job.name
    if target.exists():
        # Do not replay a timeout or overwrite an already imported application's job.
        raise OpafError('This job was already handed off; reconcile its existing state before retry.')
    temporary = Path(tempfile.mkdtemp(prefix='.fox-intake-', dir=shared_root))
    try:
        intake = temporary/'intake'; intake.mkdir()
        manifest = []
        for source,raw in zip(checked,raw_files):
            (intake/source['name']).write_bytes(raw)
            manifest.append({'packaged_name':source['name'], 'source_kind':'approved_readable_source', 'sha256':source['sha256']})
        (intake/'manifest.json').write_text(json.dumps({'job_id':job.name,'source_manifest_sha256':snapshot['source_hash'],'files':manifest}), encoding='utf-8')
        temporary.rename(target)
    finally:
        if temporary.exists(): shutil.rmtree(temporary)
    return target


def run_job(job: Path):
    snapshot=json.loads((job/'source-snapshot.json').read_text(encoding='utf-8'))
    if snapshot.get('conversion_profile')=='native-table-form-v1':
        from .native_pipeline import run_native_job
        return run_native_job(job)
    if os.getenv('FOX_CONVERTER_URL'):
        return run_remote_job(job)
    if not all(os.getenv(key) for key in ['FOX_CONVERTER_JOBS_ROOT','FOX_OPAF_CREDENTIAL_FILE','FOX_OPAF_BASE_URL']):
        raise OpafError('OPAF handoff configuration is incomplete.')
    shared = stage_job(job, Path(os.environ['FOX_CONVERTER_JOBS_ROOT']))
    credentials = json.loads(Path(os.environ['FOX_OPAF_CREDENTIAL_FILE']).read_text())
    client = OpafClient(os.environ['FOX_OPAF_BASE_URL'], credentials['username'], credentials['password'])
    client.run(job.name)
    # Agent prose is never proof that validation, import or runtime tests passed.
    status_path = shared/'job-status.json'
    status = json.loads(status_path.read_text()) if status_path.exists() else {'state':'UNKNOWN'}
    (job/'opaf-handoff.json').write_text(json.dumps({'job_id':job.name,'state':status['state'],'workflow_id':WORKFLOW_ID}), encoding='utf-8')
    raise OpafError('OPAF handoff completed. Export, reimport and business-flow evidence must pass before package release.')


class ConverterClient:
    def __init__(self,base_url,token,*,projection=_NO_FRESH_PROJECTION):
        """Use the legacy endpoint unless an explicit valid fresh P is supplied.

        P selects configuration only. It grants no startup, storage adoption,
        target write or migration/retirement authority. Existing callers keep
        the exact original 8091 contract; explicit None is not a fallback.
        """
        if projection is _NO_FRESH_PROJECTION:
            url=urlsplit(base_url)
            if url.scheme!='http' or url.hostname!='127.0.0.1' or url.port!=8091 or url.path not in ('','/') or url.query or url.fragment or url.username:
                raise OpafError('Converter must use the configured VM loopback endpoint.')
            self._port=8091
        else:
            # Legacy measured-module loaders need no fresh-install dependency.
            # A fresh release must include installation.py in its own closure.
            from .installation import FreshProjectionError, converter_port, validate_projection
            try:
                declared=validate_projection(projection)
                if type(base_url) is not str or base_url!=declared['converter_endpoint']:
                    raise FreshProjectionError('FRESH_CONVERTER_ENDPOINT_MISMATCH')
                self._port=converter_port(declared['converter_endpoint'])
            except FreshProjectionError:
                raise OpafError('Fresh converter endpoint must match the supplied installation projection.') from None
        self.token=token

    def request(self,method,path,payload=None,binary=False):
        conn=http.client.HTTPConnection('127.0.0.1',self._port,timeout=600)
        try:
            conn.request(method,path,json.dumps(payload) if payload is not None else None,
                         {'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
            response=conn.getresponse();raw=response.read(8_000_001)
            if response.status not in (200,201) or len(raw)>8_000_000:
                raise OpafError(f'Converter step failed (HTTP {response.status}); the job is retained. No automatic replay.',response.status)
            return raw if binary else json.loads(raw)
        except (OSError,http.client.HTTPException):
            raise OpafError('Converter transport failed. Reconcile the existing job before retrying.') from None
        finally: conn.close()


def run_remote_job(job:Path):
    if not re.fullmatch(r'fox-[a-f0-9]{20}',job.name) or job.is_symlink():
        raise OpafError('Invalid FOX job.')
    snapshot=json.loads((job/'source-snapshot.json').read_text())
    # Reuse the same strict local handoff validation, in ephemeral local scratch.
    with tempfile.TemporaryDirectory(prefix='fox-preflight-') as temp:
        stage_job(job,Path(temp))
    credentials=json.loads(Path(os.environ['FOX_OPAF_CREDENTIAL_FILE']).read_text())
    gateway=ConverterClient(os.environ['FOX_CONVERTER_URL'],credentials['converter_token'])
    path='/fox/jobs/'+job.name
    gateway.request('POST',path,{'source_hash':snapshot['source_hash'],'files':snapshot['files']})
    client=OpafClient(os.environ['FOX_OPAF_BASE_URL'],credentials['username'],credentials['password'])
    client.run(job.name)
    state=gateway.request('GET',path)
    (job/'opaf-handoff.json').write_text(json.dumps(state),encoding='utf-8')
    if state.get('state')!='IMPORTED':
        raise OpafError('OPAF did not produce an imported application. Validation evidence and source are retained.')
    evidence=gateway.request('POST',path+'/release',{})
    if evidence.get('job_id')!=job.name or evidence.get('source_manifest_sha256')!=snapshot['source_hash']:
        raise OpafError('Release evidence does not match this source version.')
    raw=gateway.request('GET',path+'/package',binary=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)) or len(names)>500:
            raise OpafError('Invalid package structure.')
        if sum(i.file_size for i in archive.infolist())>20_000_000:
            raise OpafError('Package exceeds MVP size limit.')
        manifest=json.loads(archive.read('manifest.json'))
        if set(names)!=set(manifest)|{'manifest.json'}:
            raise OpafError('Package manifest is incomplete.')
        for name,digest in manifest.items():
            if name.startswith('/') or '\\' in name or '..' in name.split('/') or hashlib.sha256(archive.read(name)).hexdigest()!=digest:
                raise OpafError('Package integrity check failed.')
        if json.loads(archive.read('evidence/release-evidence.json'))!=evidence:
            raise OpafError('Packaged evidence differs from the release receipt.')
    temp=job/'.apex-package-new.zip';temp.write_bytes(raw);temp.replace(job/'apex-package.zip')
    (job/'release-evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
