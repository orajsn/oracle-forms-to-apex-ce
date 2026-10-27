"""Leased, split JSN cutover using the retained-candidate and snapshot tools.

No CLI exposes service actions. The Windows operator must hold the actual
preactivation C/F/G leases and supply the actual snapshot capability. Stop,
capture/restore, activation and public release remain separate explicit calls.
There is no rollback, delete, replacement, network/IAM or database operation.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
SCOPE = 'fox-leased-paired-cutover-v1'
SHA = re.compile(r'[a-f0-9]{64}\Z')
READINESS_SHA = 'de48c340ebe73fa5a97a6db2bee12e5c2e1a40ef6a22a77c8327af97359e90b3'
LIVE_ROLLBACK_SCAN = r'''
import hashlib,json,os,pathlib,re,sqlite3,stat,sys
def need(ok):
 if not ok:raise RuntimeError('LIVE_SOURCE_NOT_SAFE_FOR_G_RECOVERY')
def unique(rows):
 result={}
 for key,value in rows:
  need(key not in result);result[key]=value
 return result
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
root=pathlib.Path('/home/opc/fox/data/jobs')
need(root.is_dir() and root.resolve()==root)
for part in (root,*root.parents):need(not part.is_symlink())
def legacy_v0_binding(value,job_id):
 # The original G app defaults this pre-profile schema to its legacy view.
 # Prove full saved-source/DB identity; never relabel, approve or execute it.
 need(set(value)=={'project','source_hash','files','inventory'})
 project=value['project'];source_hash=value['source_hash'];files=value['files'];inventory=value['inventory']
 need(type(job_id) is str and re.fullmatch('fox-[a-f0-9]{20}',job_id)
  and type(project) is str and re.fullmatch('[a-f0-9]{32}',project)
  and type(source_hash) is str and re.fullmatch('[a-f0-9]{64}',source_hash)
  and type(files) is list and 0<len(files)<=50 and type(inventory) is dict
  and set(inventory)=={'dependencies','files','issues','missing_count','scope_note','source_hash'}
  and inventory['source_hash']==source_hash and type(inventory['files']) is list
  and type(inventory['dependencies']) is list and type(inventory['issues']) is list
  and type(inventory['missing_count']) is int and inventory['missing_count']>=0
  and type(inventory['scope_note']) is str)
 names=set();ids=set();total=0
 for f in files:
  need(type(f) is dict and set(f)=={'id','project','name','sha256','bytes','text','created'})
  need(type(f['id']) is str and re.fullmatch('[a-f0-9]{32}',f['id']) and f['id'] not in ids
   and f['project']==project and type(f['name']) is str and 0<len(f['name'])<=250
   and f['name'] not in names and pathlib.PurePosixPath(f['name']).name==f['name']
   and f['name'] not in ('.','..') and '\\' not in f['name']
   and type(f['text']) is str and type(f['bytes']) is int and f['bytes']>0
   and type(f['created']) in (int,float) and f['created']>0
   and type(f['sha256']) is str and re.fullmatch('[a-f0-9]{64}',f['sha256']))
  raw=f['text'].encode('utf-8')
  if hashlib.sha256(raw).hexdigest()!=f['sha256']:raw=b'\xef\xbb\xbf'+raw
  need(len(raw)==f['bytes'] and hashlib.sha256(raw).hexdigest()==f['sha256'])
  total+=len(raw);need(total<=300000);names.add(f['name']);ids.add(f['id'])
 manifest='\n'.join(f['name']+':'+f['sha256'] for f in sorted(files,key=lambda f:f['name']))
 need(hashlib.sha256(manifest.encode()).hexdigest()==source_hash)
 path=pathlib.Path('/home/opc/fox/data/fox.sqlite3')
 need(path.resolve()==path and not path.is_symlink() and path.is_file())
 db=sqlite3.connect('file:'+path.as_posix()+'?mode=ro',uri=True)
 try:
  db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
  rows=db.execute('SELECT project,source_hash,state FROM runs WHERE id=?',(job_id,)).fetchall()
  need(len(rows)==1);run=dict(rows[0])
  need(run['project']==project and run['source_hash']==source_hash
   and run['state'] in ('REVIEW_REQUIRED','ACCEPTED','ATTENTION'))
  for f in files:
   rows=db.execute('SELECT id,project,name,sha256,bytes,text,created FROM sources WHERE id=? AND project=?',(f['id'],project)).fetchall()
   need(len(rows)==1 and dict(rows[0])==f)
  return hashlib.sha256(canonical({'run':run,'source_manifest_sha256':source_hash,
   'source_ids':sorted(ids),'classification':'retained-legacy-v0-no-processing-authority'})).hexdigest()
 finally:db.close()
def scan():
 result={};items=sorted(root.iterdir());need(len(items)<=10000)
 for job in items:
  need(not job.is_symlink())
  if not job.is_dir():continue
  path=job/'source-snapshot.json';info=path.lstat()
  need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=64*1024*1024 and path.resolve()==path)
  with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
   opened=os.fstat(stream.fileno());raw=stream.read(64*1024*1024+1);after=os.fstat(stream.fileno())
  fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  need(len(raw)==info.st_size and all(getattr(info,k)==getattr(opened,k)==getattr(after,k)==getattr(path.stat(),k) for k in fields))
  value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False))
  need(type(value) is dict and 'native_project' not in value)
  if 'conversion_profile' in value:
   need(value['conversion_profile'] in ('native-table-form-v1','legacy-html-prototype-v1'))
   binding=None
  else:binding=legacy_v0_binding(value,job.name)
  for marker in ('native-project-pipeline','project-technical-verification'):
   need(not (job/marker).exists() and not (job/marker).is_symlink())
  result[job.name]={'source_sha256':hashlib.sha256(raw).hexdigest(),'legacy_v0_binding_sha256':binding}
 return result
before=scan();need(scan()==before)
print(json.dumps({'project_history_present':False,'jobs_checked':len(before),
 'source_state_sha256':hashlib.sha256(canonical(before)).hexdigest(),'read_only':True},sort_keys=True))
'''


class CutoverError(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise CutoverError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)',value),
         'EXACT_UTC_TIMESTAMP_REQUIRED')
    return datetime.fromisoformat(value.replace('Z','+00:00'))


def remote_helper_path(installation_path):
    need(type(installation_path) is str and '\\' not in installation_path
         and not any(ord(c) < 32 for c in installation_path), 'REMOTE_INSTALLATION_PATH_INVALID')
    path = PurePosixPath(installation_path)
    need(path.is_absolute() and str(path) == installation_path and '..' not in path.parts,
         'REMOTE_INSTALLATION_PATH_INVALID')
    return str(path.parent/'cutover_project_release.py')


def validate_created_destination(created, admission_raw, release_sha256):
    admission = json.loads(admission_raw)
    need(type(created) is dict and created.get('release_sha256') == release_sha256
         and created.get('admission_sha256') == sha(admission_raw)
         and type(created.get('candidates')) is dict and set(created['candidates']) == {'fox','converter'}
         and admission.get('current_release_sha256') == release_sha256,
         'CREATED_DESTINATION_BINDING_CHANGED')
    for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
        recorded = created['candidates'][role]
        need(type(recorded) is dict and set(recorded) == {'id','image','name'}
             and {key:recorded[key] for key in ('id','image')} == admission['infrastructure'][name],
             'CREATED_CONTAINER_DIFFERS_FROM_PINNED_ADMISSION')
    return admission


def validate_snapshot_bindings(A, config, old):
    refs = config['protected_sources'];roles = config['role_paths']
    required = {'fox':{'/data':roles['fox-data'],'/run/fox-opaf':refs['opaf-client']['path'],
                       '/run/fox-native/profile.json':refs['baseline-fox-profile']['path']},
                'forms2apex-mcp':{'/opt/forms2apex/outputs/jobs':roles['converter-jobs'],
                    '/home/converter/.dbtools':refs['sqlcl-connections']['path'],
                    '/opt/forms2apex/wallet':refs['wallet']['path'],
                    '/run/fox-target/profile.json':refs['baseline-target-profile']['path']}}
    for name,mounts in required.items():
        actual = A.mount_map(old[name])
        need(all(actual.get(destination,(None,None))[0] == source for destination,source in mounts.items()),
             'SNAPSHOT_SOURCE_DIFFERS_FROM_ACTUAL_G_MOUNT')
    for label,unit in (('fox-unit','fox.service'),('converter-unit','forms2apex-mcp.service'),('tls-unit','fox-https.service')):
        need(refs[label]['path'] == A.UNITS[unit][0], 'SNAPSHOT_UNIT_REFERENCE_CHANGED')


def require_never_started(item):
    from fox.producer_inventory_contract import classify_row
    state = item['State']
    row = {'id':item['Id'],'name':item['Name'].lstrip('/'),'image':'sha256:'+item['Image'].removeprefix('sha256:'),
        'status':state['Status'],'running':state['Running'],'pid':state['Pid'],'exit_code':state['ExitCode'],
        'created_at':item['Created'],'started_at':state['StartedAt'],'finished_at':state['FinishedAt']}
    need(classify_row(row,datetime.now(timezone.utc).isoformat()) == 'CREATED_NEVER_STARTED',
         'PROJECT_CANDIDATE_EXECUTION_PREVENTS_G_RECOVERY')


def runtime_identity(pid, expected_python, expected_argv):
    need(type(pid) is int and pid > 0,'OPERATOR_PROCESS_NOT_CONFIRMED')
    proc = Path('/proc')/str(pid)
    before = (proc/'stat').read_text();parts = before[before.rfind(') ')+2:].split()
    need(len(parts) >= 20 and parts[19].isdigit(),'OPERATOR_PROCESS_IDENTITY_INVALID')
    executable = (proc/'exe').resolve(strict=True)
    argv = (proc/'cmdline').read_bytes().split(b'\0')
    need(argv[-1:] == [b''] and executable == Path(expected_python)
         and argv[:-1] == [value.encode() for value in expected_argv], 'OPERATOR_PROCESS_COMMAND_CHANGED')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    after = (proc/'stat').read_text();after_fields = after[after.rfind(') ')+2:].split()
    need(re.fullmatch('[a-f0-9-]{36}',boot) and len(after_fields) >= 20 and after_fields[19] == parts[19],
         'OPERATOR_PROCESS_IDENTITY_CHANGED')
    return {'pid':pid,'start_ticks':int(parts[19]),'boot_id':boot,'executable':str(executable)}


def ordered_service_unit(service, admission, installation_path):
    raw = service.service_unit(admission,installation_path)
    prefix = b'[Unit]\nDescription=FOX protected product verifier\n'
    need(raw.startswith(prefix) and raw.count(prefix) == 1, 'REVIEWED_UNIT_TEMPLATE_CHANGED')
    # User-unit ordering is installer configuration, not a change to the
    # frozen runtime code or existing FOX/converter units.
    directory = str(admission.source_root)
    # systemd 239 parses WorkingDirectory as a path, not an ExecStart word.
    # Limit this installer compatibility projection to an exact plain POSIX
    # path; the frozen service source and every ExecStart byte stay unchanged.
    need(re.fullmatch(r'/[A-Za-z0-9_./-]+',directory) and '..' not in PurePosixPath(directory).parts,
         'UNIT_WORKING_DIRECTORY_UNSUPPORTED')
    quoted = ('WorkingDirectory="'+directory+'"\n').encode()
    need(raw.count(quoted) == 1,'REVIEWED_WORKING_DIRECTORY_TEMPLATE_CHANGED')
    return raw.replace(prefix,prefix+b'After=fox.service forms2apex-mcp.service\nRequires=fox.service forms2apex-mcp.service\n',1).replace(
        quoted,('WorkingDirectory='+directory+'\n').encode(),1)


def verify_service_unit(A,unit):
    # systemd-analyze's offline search path omits already-generated Quadlet
    # units. Supply the real active dependency as an additional input; never
    # run generators or invent a placeholder dependency to make verification pass.
    dependency = service_state(A,'forms2apex-network.service')
    generated = PurePosixPath('/run/user/1000/systemd/generator/forms2apex-network.service')
    need(dependency['LoadState']=='loaded' and dependency['ActiveState']=='active'
         and dependency['FragmentPath']==str(generated),'ACTUAL_GENERATED_NETWORK_UNIT_REQUIRED')
    before = A.read(Path(generated))
    A.command(['/usr/bin/systemd-analyze','--user','--generators=no','verify',str(unit),str(generated)])
    need(A.read(Path(generated))==before and service_state(A,'forms2apex-network.service')==dependency,
         'GENERATED_DEPENDENCY_CHANGED_DURING_VERIFY')


def public_health():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):
            return None
    url = 'https://fox.129.213.189.48.sslip.io/api/health'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(url,timeout=15) as response:
        need(response.status == 200 and response.url == url,'PUBLIC_HEALTH_NOT_CONFIRMED')
        raw = response.read(65537)
    need(len(raw) <= 65536,'PUBLIC_HEALTH_RESPONSE_TOO_LARGE')
    value = json.loads(raw)
    need(value.get('product') == 'FOX' and value.get('status') == 'ok'
         and value.get('worker',{}).get('enabled') is True and value['worker'].get('healthy') is True,
         'PUBLIC_WORKER_NOT_HEALTHY')
    return {'url':url,'https_verified':True,'worker_healthy':True}


def _candidate_module(plan):
    path = Path(__file__).with_name('activate_project_release.py')
    raw = path.read_bytes()
    need(sha(raw) == plan['helper_sha256'], 'CANDIDATE_HELPER_CHANGED')
    name = '_reviewed_paired_candidate'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec);sys.modules[name] = module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def service_state(A, unit, *, rootful=False):
    prefix = ['sudo','-n','/usr/bin/systemctl'] if rootful else ['/usr/bin/systemctl','--user']
    raw = A.command(prefix+['show',unit,'--property=LoadState,ActiveState,SubState,MainPID,FragmentPath'])
    result = {}
    for line in raw.decode().splitlines():
        key,value = line.split('=',1)
        need(key not in result, 'SERVICE_STATE_DUPLICATE')
        result[key] = value
    need(set(result) == {'LoadState','ActiveState','SubState','MainPID','FragmentPath'}
         and result['MainPID'].isdigit(), 'SERVICE_STATE_INVALID')
    return result


def tls_container(A):
    values = A.parse(A.command(['sudo','-n','/usr/bin/podman','inspect','fox-https']))
    need(type(values) is list and len(values) == 1 and values[0]['Name'].lstrip('/') == 'fox-https'
         and values[0]['HostConfig']['AutoRemove'] is False, 'EXACT_RETAINED_TLS_REQUIRED')
    return values[0]


def configuration_signature(A, item):
    # Container names/PIDs/start times/network addresses change at the declared
    # transition. Image, process/configuration, mounts and isolation do not.
    return sha(canonical({key:item.get(key) for key in
        ('Id','Image','Config','HostConfig','Mounts','ProcessLabel','MountLabel')}))


def configuration_matches(A, item, expected):
    """Preserve the exact prestart digest, tolerating only proven OCI additions.

    Podman adds its manager and numeric stop-signal annotations at first start.
    No container setting/record is changed and no other field is ignored.
    """
    if configuration_signature(A,item) == expected:
        return True
    state,config = item.get('State'),item.get('Config')
    if not (type(state) is dict and type(config) is dict
            and type(state.get('StartedAt')) is str
            and state['StartedAt'] not in ('','0001-01-01T00:00:00Z')):
        return False
    annotations = config.get('Annotations')
    if type(annotations) is not dict:
        return False
    manager,signal = 'io.container.manager','org.opencontainers.image.stopSignal'
    if not ({manager,signal} & set(annotations)):
        return False
    if manager in annotations and annotations[manager] != 'libpod':
        return False
    if signal in annotations and not (type(config.get('StopSignal')) is int
            and 1 <= config['StopSignal'] <= 64 and annotations[signal] == str(config['StopSignal'])):
        return False
    projected = dict(item)
    projected['Config'] = dict(config)
    projected['Config']['Annotations'] = {key:value for key,value in annotations.items() if key not in (manager,signal)}
    return configuration_signature(A,projected) == expected


def read_idle(A, cid):
    program = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,'/app')
from fox.verification_recovery import VerificationRecovery
store=VerificationRecovery(Path('/data/fox.sqlite3'),enabled=True)
with store._db() as db:
 db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 jobs=store._job_ids(db)
 if not all(store._eligibility(db,j)['blocks_admission'] is False for j in jobs):raise RuntimeError('ACTIVE_OR_UNRESOLVED_WORK')
 print(json.dumps({'idle':True,'observed_jobs':len(jobs),'read_only':True}))
'''
    value = A.parse(A.command(['/usr/bin/podman','exec',cid,'/usr/local/bin/python','-I','-B','-c',program]))
    need(value.get('idle') is True and value.get('read_only') is True
         and type(value.get('observed_jobs')) is int, 'CURRENT_IDLE_STATE_UNCONFIRMED')
    return value


class HostCutover:
    def __init__(self, packet):
        need(type(packet) is dict and set(packet) == {'schema_version','scope','phase','plan','plan_sha256',
             'installation','snapshot_configuration','snapshot_configuration_sha256','backup_operation',
             'backup_completion_sha256','restore_operation','restore_completion_sha256','helper_sha256'}, 'CUTOVER_PACKET_INVALID')
        need(packet['schema_version'] == 1 and type(packet['schema_version']) is int and packet['scope'] == SCOPE
             and packet['phase'] in ('stop','activate','release','recover') and SHA.fullmatch(packet['helper_sha256'])
             and sha(Path(__file__).read_bytes()) == packet['helper_sha256'], 'REVIEWED_CUTOVER_REQUIRED')
        self.p = packet; self.A = A = _candidate_module(packet['plan'])
        self.plan = A.plan_document(canonical(packet['plan']),packet['plan_sha256'])
        self.provider, self.release = A.load_bindings(self.plan)
        self.R = self.plan['release']['sha256'];self.stage = A.PARENT/self.R
        A.private_dir(self.stage)
        need(A.read(self.stage/'plan.json',private=True) == canonical(self.plan),'CREATED_PLAN_CHANGED')
        self.created = A.parse(A.read(self.stage/'created.json',private=True))
        need(self.created.get('status') == 'STOPPED_CANDIDATES_CREATED_NOT_ACTIVATED'
             and self.created.get('plan_sha256') == packet['plan_sha256'],'COMPLETED_CANDIDATE_CREATION_REQUIRED')
        for role in ('fox','converter'):
            need(A.parse(A.read(self.stage/(role+'-created.json'),private=True)) == self.created['candidates'][role],
                 'CREATED_CONTAINER_ID_CHANGED')
        self.old = A.parse(A.read(self.stage/'before.private.json',private=True))
        reference = packet['installation']
        need(type(reference) is dict and set(reference) == {'path','sha256'} and SHA.fullmatch(reference['sha256']),
             'PINNED_INSTALLATION_REQUIRED')
        service = importlib.import_module('qa.operator.hosted_service')
        self.admission = service.HostedAdmission(reference['path'],expected_sha256=reference['sha256'])
        need(self.admission.release == self.R and self.admission.reference_raw['admission'] == A.read(self.stage/'admission.json',private=True),
             'INSTALLATION_DESTINATION_CHANGED')
        validate_created_destination(self.created,self.admission.reference_raw['admission'],self.R)
        self.admission.archive.read()
        self.service = service
        self.snapshot = importlib.import_module('qa.operator.hosted_snapshot')
        self.snapshot_engine = importlib.import_module('qa.operator.snapshot')
        snapshot_raw = base64.b64decode(packet['snapshot_configuration'],validate=True)
        self.snapshot_config = self.snapshot.configuration_document(snapshot_raw,packet['snapshot_configuration_sha256'])
        need(self.snapshot_config['mode'] == 'pre-hosted-g'
             and self.snapshot_config['runtime']['fox'] == {'id':A.BASE['fox'][0],'image':'sha256:'+A.BASE['fox'][1]}
             and self.snapshot_config['runtime']['converter'] == {'id':A.BASE['forms2apex-mcp'][0],'image':'sha256:'+A.BASE['forms2apex-mcp'][1]}
             and self.snapshot_config['source_sha256'] == {name:sha(Path(self.snapshot.__file__).with_name(name).read_bytes())
                 for name in ('snapshot.py','hosted_snapshot.py')}, 'BASELINE_SNAPSHOT_CONFIGURATION_CHANGED')
        validate_snapshot_bindings(A,self.snapshot_config,self.old)

    def local_guards(self):
        A = self.A;A.host_identity()
        for path,expected in A.UNITS.values():
            need(sha(A.read(Path(path))) == expected,'EXISTING_UNIT_CHANGED')
        need(A.read(self.stage/'plan.json',private=True) == canonical(self.plan),'CREATED_PLAN_CHANGED')
        self.service.verify_inventory(self.admission.source_root,self.admission.reference_raw['inventory'])
        self.admission.archive.read()
        opaf = A.inspect_container('oracle-applied-ai-label')
        need(opaf['Id'] == A.BASE['oracle-applied-ai-label'][0]
             and opaf['Image'].split(':')[-1] == A.BASE['oracle-applied-ai-label'][1]
             and opaf['State']['Running'] is True,'OPAF_CHANGED')

    def old_profile_sources(self):
        A = self.A
        raw = A.read(self.admission.archive.root/'manifests/idle.json',private=True)
        need(sha(raw) == A.G_RELEASE,'ORIGINAL_G_MANIFEST_CHANGED')
        manifest = A.parse(raw)
        need(sha(A.read(Path(A.BASE_PROFILES['fox']))) == manifest['native_profile_sha256'],
             'ORIGINAL_G_PROFILE_CHANGED')
        expected = A.parse(A.read(Path(self.plan['bundle_root'])/'deployment/target-profile.jsn.json'))
        need(A.canonical(A.parse(A.read(Path(A.BASE_PROFILES['converter'])))) == A.canonical(expected),
             'ORIGINAL_CONVERTER_PROFILE_CHANGED')

    def live_rollback_guard(self):
        # The namespace grants read access to the existing app-owned files;
        # this fixed scan never imports an app, copies data or alters ACLs.
        raw = self.A.command(['/usr/bin/podman','unshare',self.provider['python']['path'],
            '-I','-B','-c',LIVE_ROLLBACK_SCAN],timeout=120,maximum=65536)
        value = self.A.parse(raw)
        need(type(value) is dict and set(value) == {'project_history_present','jobs_checked','source_state_sha256','read_only'}
             and value['project_history_present'] is False and value['read_only'] is True
             and type(value['jobs_checked']) is int and value['jobs_checked'] >= 0
             and SHA.fullmatch(value['source_state_sha256']), 'ACTUAL_SOURCE_COMPATIBILITY_UNCONFIRMED')
        return value

    def stopped_idle(self):
        # Recheck the stopped SQLite state after HTTP shutdown/drain. This
        # closes the race in which an already-received G request could queue
        # work after the pre-stop read. Import only the frozen B readers.
        program = r'''
import json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+'/fox',sys.argv[1]+'/converter']
from fox.verification_recovery import VerificationRecovery
store=VerificationRecovery(Path('/home/opc/fox/data/fox.sqlite3'),enabled=True)
with store._db(False) as db:
 db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 jobs=store._job_ids(db)
 if not all(store._eligibility(db,j)['blocks_admission'] is False for j in jobs):raise RuntimeError('ACTIVE_OR_UNRESOLVED_WORK')
 print(json.dumps({'idle':True,'observed_jobs':len(jobs),'read_only':True}))
'''
        value = self.A.parse(self.A.command(['/usr/bin/podman','unshare',self.provider['python']['path'],
            '-I','-B','-c',program,self.plan['bundle_root']],timeout=120,maximum=65536))
        need(value.get('idle') is True and value.get('read_only') is True
             and type(value.get('observed_jobs')) is int,'STOPPED_BACKEND_NOT_IDLE')
        return value

    def record(self, name, value):
        self.A.create_file(self.stage/name,canonical(value))

    def effect(self, name, argv):
        self.local_guards()
        return self.A.create_once(self.stage,'cutover-'+name,argv,self.p['plan_sha256'])

    def require_stopped(self, identity, name, image):
        value = self.A.inspect_container(identity)
        need(value['Name'].lstrip('/') == name and value['Image'].split(':')[-1] == image.removeprefix('sha256:')
             and value['State']['Running'] is False and value['State']['Pid'] == 0,'EXACT_STOPPED_CONTAINER_REQUIRED')
        originals = {item['Id']:item for item in self.old.values()}
        if identity in originals:
            original = originals[identity]
            need(configuration_signature(self.A,value) == configuration_signature(self.A,original)
                 and value['State']['StartedAt'] == original['State']['StartedAt']
                 and set(value['NetworkSettings']['Networks']) == set(original['NetworkSettings']['Networks']),
                 'RETAINED_G_CHANGED_OR_RESTARTED')
        return value

    def require_tls(self, running):
        value = tls_container(self.A)
        pin = self.snapshot_config['runtime']['tls']
        need(value['Id'] == pin['id'] and value['Image'].split(':')[-1] == pin['image'][7:]
             and value['State']['Running'] is running and (running or value['State']['Pid'] == 0),'TLS_IDENTITY_OR_STATE_CHANGED')
        state = service_state(self.A,'fox-https.service',rootful=True)
        need(state['LoadState'] == 'loaded' and state['ActiveState'] == ('active' if running else 'inactive')
             and state['FragmentPath'] == self.A.UNITS['fox-https.service'][0], 'TLS_SERVICE_STATE_CHANGED')

    def stop(self):
        A = self.A
        need(not (self.stage/'cutover-stopped.json').exists(),'PRIOR_STOP_PRESERVED_NO_REPLAY')
        need(A.baseline_signature(A.baseline()) == A.baseline_signature(self.old),'G_BASELINE_CHANGED')
        A.validate_bound_sources(self.old)
        self.admission.preflight();self.old_profile_sources();self.require_tls(True)
        compatible_sources = self.live_rollback_guard()
        need(service_state(A,'fox-product-verifier.service')['LoadState'] == 'not-found','VERIFIER_ALREADY_INSTALLED')
        self.effect('stop-tls',['sudo','-n','/usr/bin/systemctl','stop','fox-https.service'])
        self.require_tls(False)
        idle = read_idle(A,A.BASE['fox'][0])
        for unit,name in (('fox.service','fox'),('forms2apex-mcp.service','forms2apex-mcp')):
            self.effect('stop-'+name,['/usr/bin/systemctl','--user','stop',unit])
            self.require_stopped(A.BASE[name][0],name,A.BASE[name][1])
            need(service_state(A,unit)['ActiveState'] == 'inactive','SERVICE_STOP_UNCONFIRMED')
        self.snapshot._host_guard(self.snapshot_config)
        stopped_idle = self.stopped_idle()
        result = {'status':'G_STOPPED_TLS_HELD','release_sha256':self.R,
            'installation_sha256':self.p['installation']['sha256'],'snapshot_configuration_sha256':self.p['snapshot_configuration_sha256'],
            'idle':idle,'stopped_idle':stopped_idle,'prestop_source_compatibility':compatible_sources,
            'stopped_at_utc':datetime.now(timezone.utc).isoformat(),'automatic_replay_permitted':False}
        self.record('cutover-stopped.json',result)
        return result

    def _backup(self):
        name = self.p['backup_operation']
        need(type(name) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}',name)
             and SHA.fullmatch(self.p['backup_completion_sha256'] or ''),'EXACT_COMPLETED_BACKUP_REQUIRED')
        stopped = self.A.parse(self.A.read(self.stage/'cutover-stopped.json',private=True))
        need(stopped['status'] == 'G_STOPPED_TLS_HELD' and stopped['release_sha256'] == self.R
             and stopped['installation_sha256'] == self.p['installation']['sha256']
             and stopped['snapshot_configuration_sha256'] == self.p['snapshot_configuration_sha256'],'STOP_RECEIPT_CHANGED')
        path = Path(self.snapshot_config['output_root'])/name
        receipt = self.snapshot._verified_completion(self.snapshot_engine,path,self.snapshot_config,
            self.p['snapshot_configuration_sha256'],expected_sha=self.p['backup_completion_sha256'],capture_only=True)
        stop_time,completed,now = utc(stopped['stopped_at_utc']),utc(receipt['completed_at_utc']),datetime.now(timezone.utc)
        before,after = (self.snapshot.parse(self.snapshot_engine._read(path/name)) for name in ('before.json','after.json'))
        before_time,after_time = utc(before['observed_at_utc']),utc(after['observed_at_utc'])
        need(stop_time <= before_time <= after_time <= completed and (completed-now).total_seconds() <= 5,
             'BACKUP_NOT_BOUND_TO_THIS_STOP_OR_FUTURE')
        restored = self.p['restore_operation']
        need(type(restored) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}',restored) and restored != name
             and SHA.fullmatch(self.p['restore_completion_sha256'] or ''), 'EXACT_ISOLATED_RESTORE_PROOF_REQUIRED')
        restore_path = Path(self.snapshot_config['output_root'])/restored
        proof = self.snapshot._verified_completion(self.snapshot_engine,restore_path,self.snapshot_config,
            self.p['snapshot_configuration_sha256'],expected_sha=self.p['restore_completion_sha256'])
        restore_intent = self.snapshot.parse(self.snapshot_engine._read(restore_path/'intent.json'))
        need(proof['action'] == 'restore' and restore_intent['backup'] == str(path/'snapshot')
             and restore_intent['backup_completion_sha256'] == self.p['backup_completion_sha256']
             and completed <= utc(proof['completed_at_utc'])
             and (utc(proof['completed_at_utc'])-now).total_seconds() <= 5, 'RESTORE_PROOF_DOES_NOT_MATCH_THIS_CAPTURE')
        return receipt

    def activate(self):
        A = self.A
        need(not (self.stage/'project-start-floor.json').exists(),'PROJECT_START_ALREADY_ATTEMPTED_NO_REPLAY')
        self.local_guards();self.require_tls(False);self._backup()
        self.snapshot._host_guard(self.snapshot_config)
        self.stopped_idle()
        profile = A.parse(A.read(Path(self.release['opaf_profile']['host_path'])))
        boundaries = {}
        for role,oldname in (('fox','fox'),('converter','forms2apex-mcp')):
            record = self.created['candidates'][role]
            item = A.inspect_container(record['id'])
            env = A.new_environment(role,self.old[oldname],self.R,profile)
            _,mounts = A.candidate_argv(role,self.old[oldname],self.plan,self.release,self.stage)
            A.check_candidate(item,role,self.plan,self.release,env,mounts,baseline_item=self.old[oldname])
            boundaries[role] = configuration_signature(A,item)
            self.require_stopped(A.BASE[oldname][0],oldname,A.BASE[oldname][1])
        retained = {'fox':'fox-pre-project-'+self.R[:16],'converter':'forms2apex-pre-project-'+self.R[:16]}
        existing = set(A.command(['/usr/bin/podman','ps','-a','--format','{{.Names}}']).decode().splitlines())
        need(not set(retained.values()) & existing,'RETAINED_NAMES_ALREADY_EXIST')
        self.record('cutover-boundaries.json',{'new':boundaries,'retained_names':retained,
            'backup_completion_sha256':self.p['backup_completion_sha256']})
        for role,oldname in (('fox','fox'),('converter','forms2apex-mcp')):
            self.effect('retain-'+role,['/usr/bin/podman','rename',A.BASE[oldname][0],retained[role]])
            self.require_stopped(A.BASE[oldname][0],retained[role],A.BASE[oldname][1])
            self.effect('assign-'+role,['/usr/bin/podman','rename',self.created['candidates'][role]['id'],oldname])
            item = self.require_stopped(self.created['candidates'][role]['id'],oldname,self.release['images'][role])
            need(configuration_signature(A,item) == boundaries[role],'CANDIDATE_CHANGED_DURING_RENAME')
        # An uncertain startup is never permission to run old G on new state.
        self.record('project-start-floor.json',{'release_sha256':self.R,'project_aware_code_required':True,
            'automatic_g_rollback_permitted':False,'backup_completion_sha256':self.p['backup_completion_sha256']})
        for role,unit,name in (('converter','forms2apex-mcp.service','forms2apex-mcp'),('fox','fox.service','fox')):
            self.effect('start-'+role,['/usr/bin/systemctl','--user','start',unit])
            self.await_started(role,name,boundaries[role])
        self.await_fox_health()
        self.require_tls(False)
        checked = self.admission.check()
        need(checked['status'] == 'CHECKED_NOT_STARTED','NEW_HISTORY_ADMISSION_NOT_READY')
        read_idle(A,self.created['candidates']['fox']['id'])
        result = {'status':'PROJECT_RUNNING_TLS_HELD','release_sha256':self.R,
            'installation_sha256':self.p['installation']['sha256'],'admission_sha256':self.created['admission_sha256'],
            'backup_completion_sha256':self.p['backup_completion_sha256'],'retained_names':retained,
            'retained_g_ids':{role:A.BASE[name][0] for role,name in (('fox','fox'),('converter','forms2apex-mcp'))},
            'history_checked':True,'verifier_started':False,'tls_released':False,'automatic_replay_permitted':False}
        self.record('cutover-prepared.json',result)
        return result

    def await_started(self, role, name, expected, *, timeout=120):
        """Observe the same single start; never call start/restart while waiting."""
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            item = self.A.inspect_container(self.created['candidates'][role]['id'])
            need(item['Id'] == self.created['candidates'][role]['id'] and item['Name'].lstrip('/') == name
                 and item['Image'].removeprefix('sha256:') == self.release['images'][role][7:],
                 'STARTED_RUNTIME_IDENTITY_CHANGED')
            state = item['State']
            if state['Running'] is True and type(state['Pid']) is int and state['Pid'] > 0:
                need(configuration_matches(self.A,item,expected),'NEW_RUNTIME_CONFIGURATION_CHANGED')
                return item
            need(not (state['Status'] in ('exited','stopped','dead')
                 and state['StartedAt'] not in ('','0001-01-01T00:00:00Z')),
                 'NEW_RUNTIME_EXITED_NO_REPLAY')
            time.sleep(1)
        raise CutoverError('NEW_RUNTIME_START_TIMEOUT_STATUS_ONLY')

    def await_fox_health(self, *, timeout=120):
        """Wait for app initialization before the full independent admission read."""
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                request=urllib.request.Request('http://127.0.0.1:8100/api/health',method='GET')
                with urllib.request.urlopen(request,timeout=2) as response:
                    value=json.loads(response.read(65537))
                    if response.status==200 and type(value)is dict and value.get('product')=='FOX':
                        return
            except (OSError,ValueError):
                pass
            time.sleep(1)
        raise CutoverError('FOX_INITIAL_HEALTH_TIMEOUT_STATUS_ONLY')

    def resume_after_converter_start(self):
        """One explicit forward continuation; no converter or phase replay."""
        need(type(self) is HostCutover,'EXACT_FORWARD_CONTROLLER_REQUIRED')
        A=self.A
        with A.held_stage(self.stage):
            self.local_guards();self.require_tls(False);self._backup();self.stopped_idle()
            need(not (self.stage/'cutover-prepared.json').exists()
                 and not (self.stage/'forward-activation-intent.json').exists(),
                 'PRIOR_FORWARD_ACTIVATION_PRESERVED_NO_REPLAY')
            floor=A.parse(A.read(self.stage/'project-start-floor.json',private=True))
            need(floor == {'release_sha256':self.R,'project_aware_code_required':True,
                 'automatic_g_rollback_permitted':False,'backup_completion_sha256':self.p['backup_completion_sha256']},
                 'ORIGINAL_START_FLOOR_CHANGED')
            boundaries=A.parse(A.read(self.stage/'cutover-boundaries.json',private=True))
            for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
                self.require_stopped(A.BASE[name][0],boundaries['retained_names'][role],A.BASE[name][1])
            converter=A.inspect_container(self.created['candidates']['converter']['id'])
            need(converter['Name'].lstrip('/')=='forms2apex-mcp' and converter['State']['Running'] is True
                 and type(converter['State']['Pid']) is int and converter['State']['Pid']>0
                 and configuration_matches(A,converter,boundaries['new']['converter']),
                 'FORWARD_CONVERTER_NOT_EXACT_RUNNING')
            exited=A.parse(A.read(self.stage/'cutover-start-converter-create-exit.json',private=True))
            intent=A.parse(A.read(self.stage/'cutover-start-converter-create-intent.json',private=True))
            need(exited.get('exit_code')==0 and exited.get('observed_original_process') is True
                 and intent.get('plan_sha256')==self.p['plan_sha256']
                 and intent.get('argv_sha256')==sha(canonical(['/usr/bin/systemctl','--user','start','forms2apex-mcp.service'])),
                 'ORIGINAL_CONVERTER_START_NOT_RECONCILED')
            fox=A.inspect_container(self.created['candidates']['fox']['id']);require_never_started(fox)
            need(fox['Name'].lstrip('/')=='fox' and configuration_signature(A,fox)==boundaries['new']['fox']
                 and not (self.stage/'cutover-start-fox-create-intent.json').exists(),
                 'FORWARD_FOX_MUST_BE_UNATTEMPTED')
            need(service_state(A,'fox.service')['ActiveState']=='inactive'
                 and service_state(A,'forms2apex-mcp.service')['ActiveState']=='active',
                 'FORWARD_SERVICE_STATE_CHANGED')
            converter_identity = {key:converter['State'][key] for key in ('Pid','StartedAt')}
            self.record('forward-activation-intent.json',{'release_sha256':self.R,
                'installation_sha256':self.p['installation']['sha256'],
                'converter_restart_permitted':False,'g_rollback_permitted':False,
                'observed_converter_process':converter_identity,
                'automatic_replay_permitted':False,'controller_sha256':self.p['helper_sha256']})
            self.effect('forward-start-fox',['/usr/bin/systemctl','--user','start','fox.service'])
            self.await_started('fox','fox',boundaries['new']['fox']);self.await_fox_health()
            self.current_pair();self.require_tls(False)
            current_converter=A.inspect_container(self.created['candidates']['converter']['id'])
            need({key:current_converter['State'][key] for key in ('Pid','StartedAt')}==converter_identity,
                 'FORWARD_CONVERTER_PROCESS_CHANGED_DURING_FOX_START')
            need(self.admission.check()['status']=='CHECKED_NOT_STARTED','NEW_HISTORY_ADMISSION_NOT_READY')
            read_idle(A,self.created['candidates']['fox']['id'])
            result={'status':'PROJECT_RUNNING_TLS_HELD','release_sha256':self.R,
                'installation_sha256':self.p['installation']['sha256'],'admission_sha256':self.created['admission_sha256'],
                'backup_completion_sha256':self.p['backup_completion_sha256'],'retained_names':boundaries['retained_names'],
                'retained_g_ids':{role:A.BASE[name][0] for role,name in (('fox','fox'),('converter','forms2apex-mcp'))},
                'history_checked':True,'verifier_started':False,'tls_released':False,'automatic_replay_permitted':False}
            self.record('cutover-prepared.json',result)
            self.record('forward-activation-complete.json',{'status':'FORWARD_ACTIVATION_CONFIRMED',
                'prepared_sha256':sha(canonical(result)),'converter_restart_requested':False,
                'source_or_history_relabelled':False,'automatic_replay_permitted':False})
            return result

    def install_forward_admin_reference(self, secret):
        """Create the planned private reference, never rotate a DB credential."""
        need(type(self) is HostCutover,'EXACT_FORWARD_CONTROLLER_REQUIRED')
        with self.A.held_stage(self.stage):
            self.local_guards();self.current_pair();self.require_tls(False);self._backup()
            prepared=self.A.parse(self.A.read(self.stage/'cutover-prepared.json',private=True))
            need(prepared['status']=='PROJECT_RUNNING_TLS_HELD' and prepared['release_sha256']==self.R,
                 'FORWARD_PREPARED_RECORD_REQUIRED')
            self.admission.provider.check_public_mounts()
            need(type(secret)is str and re.fullmatch(r'[A-Za-z0-9_!#%+.,:=?@^*-]{12,128}',secret),
                 'PROTECTED_ADMIN_VALUE_INVALID')
            target=Path(self.provider['admin_secret_file'])
            need(str(target)=='/home/opc/.config/fox-operator-secrets/admin-password'
                 and not target.exists() and not target.is_symlink(), 'NEW_ADMIN_REFERENCE_REQUIRED')
            self.record('forward-admin-reference-intent.json',{'target':str(target),
                'secret_value_recorded':False,'automatic_replay_permitted':False})
            raw=(secret+'\n').encode('ascii');self.A.create_file(target,raw)
            need(self.A.read(target,private=True)==raw,'ADMIN_REFERENCE_READBACK_UNCONFIRMED')
            result={'status':'PROTECTED_ADMIN_REFERENCE_INSTALLED','secret_value_returned':False,
                'database_credential_changed':False,'automatic_replay_permitted':False}
            self.record('forward-admin-reference-complete.json',result)
            return result

    def current_pair(self):
        A = self.A
        boundaries = A.parse(A.read(self.stage/'cutover-boundaries.json',private=True))
        for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
            value = A.inspect_container(name)
            need(value['Id'] == self.created['candidates'][role]['id'] and value['State']['Running'] is True
                 and configuration_matches(A,value,boundaries['new'][role]),'ACTIVE_PAIRED_RUNTIME_CHANGED')
            self.require_stopped(A.BASE[name][0],boundaries['retained_names'][role],A.BASE[name][1])
        converter = A.inspect_container('forms2apex-mcp')
        need(converter['NetworkSettings']['Networks']['forms2apex']['IPAddress'] == '10.89.1.3',
             'MCP_PRIVATE_ADDRESS_CHANGED')

    def _operator_argv(self):
        return [self.provider['python']['path'],'-I','-B',
            str(Path(self.plan['bundle_root'])/'qa/operator/hosted_service.py'),'run','--installation',
            self.p['installation']['path'],'--installation-sha256',self.p['installation']['sha256'],'--apply']

    def operator_identity(self):
        state = service_state(self.A,'fox-product-verifier.service')
        need(state['LoadState'] == 'loaded' and state['ActiveState'] == 'active' and state['SubState'] == 'running'
             and state['FragmentPath'] == '/home/opc/.config/systemd/user/fox-product-verifier.service',
             'OPERATOR_SERVICE_NOT_RUNNING')
        return runtime_identity(int(state['MainPID']),self.provider['python']['path'],self._operator_argv())

    def first_idle(self, *, timeout=120):
        identity = self.operator_identity();deadline = time.monotonic()+timeout
        journal = self.admission.provider.path('journal')/self.R[:16]
        while time.monotonic() < deadline:
            need(self.operator_identity() == identity,'OPERATOR_PROCESS_REPLACED_DURING_STARTUP')
            if journal.exists():
                members = sorted(journal.iterdir());witness = None;publishing = False
                for directory in members:
                    if directory.name in ('release.json','worker.lock'):continue
                    need(re.fullmatch('session-[a-f0-9]{24}',directory.name) and directory.is_dir()
                         and not directory.is_symlink(),'OPERATOR_JOURNAL_MEMBERS_UNEXPECTED')
                    if (directory/'attention.json').exists():
                        raise CutoverError('OPERATOR_REPORTED_ATTENTION_NO_REPLAY')
                    try:
                        header = self.A.parse(self.A.read(directory/'session.json',private=True))
                        intent_raw = self.A.read(directory/'p0001-claim.intent.json',private=True)
                        result_raw = self.A.read(directory/'p0001-claim.complete.json',private=True)
                        intent,result = self.A.parse(intent_raw),self.A.parse(result_raw)
                    except (FileNotFoundError,json.JSONDecodeError):
                        publishing = True;continue  # A create-only publication can be in flight.
                    except self.A.ActivationError as error:
                        if str(error) == 'INPUT_CHANGED_DURING_READ':publishing = True;continue
                        raise
                    need(set(header) == {'scope','release_sha256','started_at_utc','bounds','startup_authorized'}
                        and header['scope'] == 'fox-product-verifier-session-v1'
                        and header['release_sha256'] == self.R and header['startup_authorized'] is True
                        and canonical(header['bounds']) == canonical(self.admission.document['bounds'])
                        and (utc(header['started_at_utc'])-datetime.now(timezone.utc)).total_seconds() <= 5
                        and intent == {
                        'scope':'fox-product-verifier-step-v1','release_sha256':self.R,'step':'p0001-claim','binding_sha256':None}
                        and result == {'scope':'fox-product-verifier-step-result-v1','release_sha256':self.R,
                            'intent_sha256':sha(intent_raw),'result':{'status':'IDLE'}}, 'OPERATOR_FIRST_CLAIM_NOT_EXACT_IDLE')
                    witness = witness or {'identity':identity,'session':directory.name,'intent_sha256':sha(intent_raw),
                        'completion_sha256':sha(result_raw),'status':'MATCHED_FIRST_IDLE_CLAIM',
                        'continuous_service_liveness_guaranteed':False}
                if witness is not None and not publishing:
                    if sorted(journal.iterdir()) != members:
                        time.sleep(1);continue  # Re-read the complete new inventory; never infer readiness.
                    need(not any((directory/'attention.json').exists() for directory in members
                        if re.fullmatch('session-[a-f0-9]{24}',directory.name)), 'OPERATOR_REPORTED_ATTENTION_NO_REPLAY')
                    need(self.operator_identity() == identity,'OPERATOR_PROCESS_CHANGED_AFTER_IDLE')
                    return witness
            time.sleep(1)
        raise CutoverError('OPERATOR_FIRST_IDLE_UNCONFIRMED_STATUS_ONLY')

    def release_public(self):
        A = self.A;self.local_guards();self.current_pair();self.require_tls(False);self._backup()
        prepared = A.parse(A.read(self.stage/'cutover-prepared.json',private=True))
        need(prepared['status'] == 'PROJECT_RUNNING_TLS_HELD' and prepared['release_sha256'] == self.R
             and prepared['installation_sha256'] == self.p['installation']['sha256'], 'PREPARED_RELEASE_CHANGED')
        need(not (self.stage/'public-release-intent.json').exists(),'PUBLIC_RELEASE_ALREADY_ATTEMPTED_NO_REPLAY')
        need(self.admission.check()['status'] == 'CHECKED_NOT_STARTED','NEW_HISTORY_ADMISSION_NOT_READY')
        read_idle(A,self.created['candidates']['fox']['id'])
        path = Path(__file__).with_name('project_release_readiness-'+READINESS_SHA+'.py');raw = A.read(path,private=True)
        need(sha(raw) == READINESS_SHA,'READINESS_HELPER_CHANGED')
        spec = importlib.util.spec_from_file_location('_reviewed_paired_readiness',path)
        readiness = importlib.util.module_from_spec(spec);sys.modules[spec.name] = readiness
        exec(compile(raw,str(path),'exec'),readiness.__dict__)
        observed = readiness.run(A,self.plan,self.release,self.created['candidates'])
        need(observed.get('status') == 'READ_ONLY_CONNECTIVITY_CONFIRMED'
             and observed.get('release_sha256') == self.R,'PAIRED_READINESS_NOT_CONFIRMED')
        self.record('paired-readiness.json',observed)
        # Check the protected reference, but never put its value in a record.
        secret = self.admission.provider.admin_secret();del secret
        need(A.command(['/usr/bin/loginctl','show-user','opc','--property=Linger','--value']).strip() == b'yes',
             'EXISTING_USER_LINGER_REQUIRED')
        unit = Path('/home/opc/.config/systemd/user/fox-product-verifier.service')
        need(not unit.exists() and not unit.is_symlink()
             and service_state(A,unit.name)['LoadState'] == 'not-found','VERIFIER_UNIT_ALREADY_PRESENT')
        journal = self.admission.provider.path('journal')/self.R[:16]
        need(not journal.exists() and not journal.is_symlink(),'VERIFIER_ALREADY_HAS_STATE_RECONCILE_FIRST')
        self.prepare_working_roots()
        raw = ordered_service_unit(self.service,self.admission,Path(self.p['installation']['path']))
        self.record('public-release-intent.json',{'release_sha256':self.R,
            'installation_sha256':self.p['installation']['sha256'],'unit_sha256':sha(raw),
            'readiness_sha256':sha(canonical(observed)),'automatic_replay_permitted':False})
        self.local_guards();A.create_file(unit,raw)
        verify_service_unit(A,unit)
        self.effect('verifier-reload',['/usr/bin/systemctl','--user','daemon-reload'])
        self.effect('verifier-enable',['/usr/bin/systemctl','--user','enable',unit.name])
        self.effect('verifier-start',['/usr/bin/systemctl','--user','start',unit.name])
        witness = self.first_idle()
        return self.finish_public(raw,witness)

    def finish_public(self,raw,witness):
        A = self.A
        unit = Path('/home/opc/.config/systemd/user/fox-product-verifier.service')
        self.record('operator-startup.json',witness)
        need(A.read(unit,private=True) == raw and self.admission.check()['status'] == 'CHECKED_NOT_STARTED',
             'OPERATOR_OR_HISTORY_CHANGED_BEFORE_PUBLIC_RELEASE')
        self.local_guards();self.current_pair();self.require_tls(False)
        self.effect('release-tls',['sudo','-n','/usr/bin/systemctl','start','fox-https.service'])
        self.require_tls(True);health = public_health()
        need(self.operator_identity() == witness['identity'],'OPERATOR_CHANGED_DURING_PUBLIC_RELEASE')
        result = {'status':'PAIRED_SERVICE_ACTIVATED','release_sha256':self.R,
            'installation_sha256':self.p['installation']['sha256'],'admission_sha256':self.created['admission_sha256'],
            'public_health':health,'operator_process':witness['identity'],'operator_first_idle_confirmed':True,
            'continuous_liveness_guaranteed':False,'model_invoked':False,'application_generated':False,
            'business_acceptance_recorded':False,'end_to_end_conversion_proven':False,'automatic_replay_permitted':False}
        self.record('public-release-complete.json',result)
        return result

    def prepare_working_roots(self):
        """Installation setup only: create absent configured roots, never chmod data."""
        A = self.A
        root = Path(self.provider['state_root'])
        A.private_dir(root)
        paths = {}
        for kind,leaf in (('native','clean-install'),('project','project-clean-install')):
            path = self.admission.provider.path(kind)
            need(path==root/leaf and path.parent.resolve()==root,'OPERATOR_WORKING_ROOT_CHANGED')
            if path.exists() or path.is_symlink():
                A.private_dir(path)
            paths[kind] = path
        # Complete all path checks before the first create. Only absent exact
        # configured directories are created; existing contents/ACLs stay intact.
        for path in paths.values():
            if not path.exists():
                path.mkdir(mode=0o700)
                A.sync(root)
            A.private_dir(path)
        return {kind:str(path) for kind,path in paths.items()}

    def observe_readiness(self):
        path = Path(__file__).with_name('project_release_readiness-'+READINESS_SHA+'.py')
        raw = self.A.read(path,private=True)
        need(sha(raw)==READINESS_SHA,'READINESS_HELPER_CHANGED')
        spec = importlib.util.spec_from_file_location('_continued_release_readiness',path)
        module = importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
        exec(compile(raw,str(path),'exec'),module.__dict__)
        result = module.run(self.A,self.plan,self.release,self.created['candidates'])
        need(result.get('status')=='READ_ONLY_CONNECTIVITY_CONFIRMED' and result.get('release_sha256')==self.R,
             'PAIRED_READINESS_NOT_CONFIRMED')
        return result

    def resume_failed_verifier_storage(self):
        """One explicit continuation after exit 2 with no journal/claim.

        Unit repair, activation, enable, backup/restore and imports are not
        repeated. Unknown/prior verifier execution always requires separate
        reconciliation, never this prerequisite-only continuation.
        """
        A = self.A
        with A.held_stage(self.stage):
            self.local_guards();self.current_pair();self.require_tls(False);self._backup()
            need(not any((self.stage/name).exists() for name in (
                'verifier-working-roots-intent.json','operator-startup.json','public-release-complete.json')),
                'VERIFIER_STORAGE_CONTINUATION_ALREADY_ATTEMPTED_NO_REPLAY')
            unit = Path('/home/opc/.config/systemd/user/fox-product-verifier.service')
            raw = ordered_service_unit(self.service,self.admission,Path(self.p['installation']['path']))
            need(A.read(unit,private=True)==raw,'REPAIRED_VERIFIER_UNIT_CHANGED')
            repair = A.parse(A.read(self.stage/'verifier-setting-repair-intent.json',private=True))
            need(repair.get('release_sha256')==self.R and repair.get('new_unit_sha256')==sha(raw),
                 'EXACT_SETTING_REPAIR_REQUIRED')
            for action in ('reload','start'):
                prefix = 'cutover-verifier-setting-repair-'+action+'-create-'
                outcome = A.parse(A.read(self.stage/(prefix+'exit.json'),private=True))
                request = A.parse(A.read(self.stage/(prefix+'intent.json'),private=True))
                argv = ['/usr/bin/systemctl','--user']+(['daemon-reload'] if action=='reload' else ['start',unit.name])
                need(outcome.get('exit_code')==0 and outcome.get('observed_original_process') is True
                     and request.get('plan_sha256')==self.p['plan_sha256']
                     and request.get('argv_sha256')==sha(canonical(argv)),'EXACT_PRIOR_VERIFIER_START_REQUIRED')
            state = service_state(A,unit.name)
            need(state['LoadState']=='loaded' and state['ActiveState']=='failed'
                 and state['SubState']=='failed' and state['MainPID']=='0','TERMINAL_FAILED_VERIFIER_REQUIRED')
            failure = A.command(['/usr/bin/systemctl','--user','show',unit.name,
                '-p','Result','-p','ExecMainCode','-p','ExecMainStatus']).decode().splitlines()
            need(set(failure)=={'Result=exit-code','ExecMainCode=1','ExecMainStatus=2'},
                 'EXACT_VERIFIER_GUARD_EXIT_REQUIRED')
            journal = self.admission.provider.path('journal')
            need(not journal.exists() and not journal.is_symlink(),'VERIFIER_HISTORY_REQUIRES_RECONCILIATION')
            paths = [self.admission.provider.path(kind) for kind in ('native','project')]
            need(all(not path.exists() and not path.is_symlink() for path in paths),
                 'EXACT_MISSING_WORKING_ROOTS_REQUIRED')
            need(self.admission.check()['status']=='CHECKED_NOT_STARTED','NEW_HISTORY_ADMISSION_NOT_READY')
            read_idle(A,self.created['candidates']['fox']['id'])
            verify_service_unit(A,unit)
            self.record('verifier-working-roots-intent.json',{'release_sha256':self.R,
                'unit_sha256':sha(raw),'installation_sha256':self.p['installation']['sha256'],
                'roots':[str(path) for path in paths],'prior_journal_absent':True,'automatic_replay_permitted':False})
            self.local_guards()
            roots = self.prepare_working_roots()
            self.record('verifier-working-roots-complete.json',{'roots':roots,'mode':'0700',
                'existing_contents_changed':False,'automatic_replay_permitted':False})
            observed = self.observe_readiness()
            self.record('paired-readiness-after-working-roots.json',observed)
            self.local_guards();self.current_pair();self.require_tls(False)
            need(A.read(unit,private=True)==raw and not journal.exists(),'VERIFIER_STATE_CHANGED_BEFORE_START')
            self.effect('verifier-working-roots-start',['/usr/bin/systemctl','--user','start',unit.name])
            witness = self.first_idle()
            return self.finish_public(raw,witness)

    def resume_failed_verifier_setting(self):
        """Repair only the proven parse rejection, never an executed verifier."""
        A = self.A
        with A.held_stage(self.stage):
            self.local_guards();self.current_pair();self.require_tls(False);self._backup()
            need(not any((self.stage/name).exists() for name in (
                'verifier-setting-repair-intent.json','operator-startup.json','public-release-complete.json')),
                'VERIFIER_REPAIR_ALREADY_ATTEMPTED_NO_REPLAY')
            unit = Path('/home/opc/.config/systemd/user/fox-product-verifier.service')
            before = A.read(unit,private=True)
            raw = ordered_service_unit(self.service,self.admission,Path(self.p['installation']['path']))
            directory = str(self.admission.source_root)
            expected_before = raw.replace(('WorkingDirectory='+directory+'\n').encode(),
                ('WorkingDirectory="'+directory+'"\n').encode(),1)
            intent = A.parse(A.read(self.stage/'public-release-intent.json',private=True))
            need(before==expected_before and before!=raw and intent=={
                'release_sha256':self.R,'installation_sha256':self.p['installation']['sha256'],
                'unit_sha256':sha(before),'readiness_sha256':sha(A.read(self.stage/'paired-readiness.json',private=True)),
                'automatic_replay_permitted':False},'EXACT_FAILED_UNIT_REQUIRED')
            for action,code in (('reload',0),('enable',0),('start',1)):
                recorded = A.parse(A.read(self.stage/('cutover-verifier-'+action+'-create-exit.json'),private=True))
                need(recorded.get('exit_code')==code and recorded.get('observed_original_process') is True,
                     'EXACT_FAILED_VERIFIER_ACTION_REQUIRED')
                request = A.parse(A.read(self.stage/('cutover-verifier-'+action+'-create-intent.json'),private=True))
                argv = ['/usr/bin/systemctl','--user']+(['daemon-reload'] if action=='reload' else [action,unit.name])
                need(request.get('plan_sha256')==self.p['plan_sha256']
                     and request.get('argv_sha256')==sha(canonical(argv)),'FAILED_VERIFIER_ACTION_CHANGED')
            state = service_state(A,unit.name)
            need(state['LoadState']=='bad-setting' and state['ActiveState']=='inactive'
                 and state['SubState']=='dead' and state['MainPID']=='0','VERIFIER_PARSE_REJECTION_REQUIRED')
            journal = self.admission.provider.path('journal')/self.R[:16]
            need(not journal.exists() and not journal.is_symlink(),'VERIFIER_EXECUTION_REQUIRES_RECONCILIATION')
            need(self.admission.check()['status']=='CHECKED_NOT_STARTED','NEW_HISTORY_ADMISSION_NOT_READY')
            read_idle(A,self.created['candidates']['fox']['id'])
            # Actual host parser first. Preserve the failed bytes and all old
            # intents/exits. The app pair and completed enable stay untouched.
            candidate = unit.with_name('fox-product-verifier-setting-'+sha(raw)+'.service')
            if candidate.exists() or candidate.is_symlink():
                need(A.read(candidate,private=True)==raw,'EXISTING_UNEXECUTED_UNIT_CANDIDATE_CHANGED')
            else:
                A.create_file(candidate,raw)
            verify_service_unit(A,candidate)
            self.record('verifier-unit-before-setting-repair.json',{
                'sha256':sha(before),'bytes_base64':base64.b64encode(before).decode()})
            self.record('verifier-setting-repair-intent.json',{
                'release_sha256':self.R,'parent_intent_sha256':sha(canonical(intent)),
                'old_unit_sha256':sha(before),'new_unit_sha256':sha(raw),'automatic_replay_permitted':False})
            self.local_guards();self.current_pair();self.require_tls(False)
            need(A.read(unit,private=True)==before and A.read(candidate,private=True)==raw,
                 'UNIT_CHANGED_BEFORE_SETTING_REPAIR')
            os.replace(candidate,unit)
            self.effect('verifier-setting-repair-reload',['/usr/bin/systemctl','--user','daemon-reload'])
            state = service_state(A,unit.name)
            need(state['LoadState']=='loaded' and state['ActiveState']=='inactive' and state['MainPID']=='0',
                 'REPAIRED_VERIFIER_UNIT_NOT_LOADED')
            self.effect('verifier-setting-repair-start',['/usr/bin/systemctl','--user','start',unit.name])
            witness = self.first_idle()
            self.record('verifier-setting-repair-complete.json',{
                'old_unit_sha256':sha(before),'new_unit_sha256':sha(raw),'operator_process':witness['identity'],
                'parent_failed_start_replayed':False,'automatic_replay_permitted':False})
            path = Path(__file__).with_name('project_release_readiness-'+READINESS_SHA+'.py')
            source = A.read(path,private=True);need(sha(source)==READINESS_SHA,'READINESS_HELPER_CHANGED')
            spec = importlib.util.spec_from_file_location('_repaired_release_readiness',path)
            readiness = importlib.util.module_from_spec(spec);sys.modules[spec.name]=readiness
            exec(compile(source,str(path),'exec'),readiness.__dict__)
            observed = readiness.run(A,self.plan,self.release,self.created['candidates'])
            need(observed.get('status')=='READ_ONLY_CONNECTIVITY_CONFIRMED' and observed.get('release_sha256')==self.R,
                 'PAIRED_READINESS_NOT_CONFIRMED')
            self.record('paired-readiness-after-setting-repair.json',observed)
            return self.finish_public(raw,witness)

    def recover_prestart(self):
        """Explicit availability recovery only; never revive the retired G pump."""
        A = self.A;self.local_guards();self.old_profile_sources()
        floor = self.stage/'project-start-floor.json'
        need(not floor.exists() and not floor.is_symlink(),'PROJECT_START_FLOOR_FORBIDS_G_RECOVERY')
        need(not (self.stage/'recover-prestart-intent.json').exists(),'PRIOR_RECOVERY_ATTEMPT_PRESERVED_NO_REPLAY')
        need(service_state(A,'fox-product-verifier.service')['LoadState'] == 'not-found', 'NEW_VERIFIER_PREVENTS_G_RECOVERY')
        source_guard = self.live_rollback_guard()
        for role,oldname in (('fox','fox'),('converter','forms2apex-mcp')):
            new = A.inspect_container(self.created['candidates'][role]['id'])
            need(new['Image'].removeprefix('sha256:') == self.release['images'][role][7:]
                 and new['Name'].lstrip('/') in {oldname,A.names(self.R)[role]}, 'RECOVERY_CANDIDATE_IDENTITY_CHANGED')
            require_never_started(new)
        # A vanished reply is not evidence that a capture worker stopped. Read
        # each declared operation's actual original identity or its true exit.
        root = self.snapshot_engine._path(Path(self.snapshot_config['output_root']),must_exist=False)
        if root.exists():
            self.snapshot_engine._privacy(root,True)
            operations = list(root.iterdir());need(len(operations) <= 128,'SNAPSHOT_OPERATION_INVENTORY_UNBOUNDED')
            for operation in operations:
                self.snapshot_engine._privacy(operation,True)
                intent = self.snapshot.parse(self.snapshot_engine._read(operation/'intent.json'))
                need(intent['configuration_sha256'] == self.p['snapshot_configuration_sha256'],
                     'OTHER_SNAPSHOT_OPERATION_PREVENTS_RECOVERY')
                if (operation/'completion.json').exists():
                    self.snapshot._verified_completion(self.snapshot_engine,operation,self.snapshot_config,
                        self.p['snapshot_configuration_sha256'])
                else:
                    worker = self.snapshot._worker_observation(self.snapshot_engine,operation,self.p['snapshot_configuration_sha256'])
                    need(worker['state'] in ('RECORDED_PROCESS_ABSENT','RECORDED_IDENTITY_NO_LONGER_PRESENT'),
                         'SNAPSHOT_WORKER_LIVE_OR_UNKNOWN_STATUS_ONLY')
        self.record('recover-prestart-intent.json',{'release_sha256':self.R,
            'candidate_execution_never_started':True,'source_compatibility':source_guard,
            'old_operator_stays_retired':True,'automatic_replay_permitted':False})
        retained = {'fox':'fox-pre-project-'+self.R[:16],'converter':'forms2apex-pre-project-'+self.R[:16]}
        for role,oldname in (('fox','fox'),('converter','forms2apex-mcp')):
            new = A.inspect_container(self.created['candidates'][role]['id'])
            if new['Name'].lstrip('/') == oldname:
                self.effect('recover-retain-new-'+role,['/usr/bin/podman','rename',new['Id'],A.names(self.R)[role]])
                require_never_started(A.inspect_container(new['Id']))
            original = A.inspect_container(A.BASE[oldname][0])
            need(original['Name'].lstrip('/') in (oldname,retained[role])
                 and configuration_signature(A,original) == configuration_signature(A,self.old[oldname])
                 and original['State']['StartedAt'] == self.old[oldname]['State']['StartedAt'],
                 'ORIGINAL_G_RUNTIME_CHANGED')
            if original['Name'].lstrip('/') == retained[role]:
                need(original['State']['Running'] is False and original['State']['Pid'] == 0,'RETAINED_G_NOT_STOPPED')
                self.effect('recover-name-'+role,['/usr/bin/podman','rename',original['Id'],oldname])
        need(self.live_rollback_guard() == source_guard,'SOURCE_CHANGED_DURING_RECOVERY_REVIEW')
        for unit,name in (('forms2apex-mcp.service','forms2apex-mcp'),('fox.service','fox')):
            item = A.inspect_container(A.BASE[name][0])
            if not item['State']['Running']:
                self.effect('recover-start-'+name,['/usr/bin/systemctl','--user','start',unit])
            item = A.inspect_container(name)
            need(item['Id'] == A.BASE[name][0] and item['State']['Running'] is True, 'G_AVAILABILITY_UNCONFIRMED')
        tls = tls_container(A);pin = self.snapshot_config['runtime']['tls']
        need(tls['Id'] == pin['id'] and tls['Image'].removeprefix('sha256:') == pin['image'][7:], 'TLS_IDENTITY_CHANGED')
        if not tls['State']['Running']:
            self.effect('recover-start-tls',['sudo','-n','/usr/bin/systemctl','start','fox-https.service'])
        self.require_tls(True)
        result = {'status':'G_AVAILABILITY_RECOVERED_OPERATOR_REMAINS_RETIRED','release_sha256':self.R,
            'data_restored':False,'candidate_execution_started':False,'partial_evidence_preserved':True,
            'managed_conversion_ready':False,'old_embedded_worker_still_enabled':True,
            'new_run_submission_not_recommended':True,'automatic_replay_permitted':False}
        self.record('recover-prestart-complete.json',result)
        return result

    def execute(self):
        with self.A.held_stage(self.stage):
            self.local_guards()
            return {'stop':self.stop,'activate':self.activate,'release':self.release_public,'recover':self.recover_prestart}[self.p['phase']]()


def host_status(plan, *, plan_sha256, admission_sha256):
    """Observe exact resources and retained markers; grants no continuation."""
    A = _candidate_module(plan)
    A.plan_document(canonical(plan),plan_sha256);A.host_identity()
    need(SHA.fullmatch(admission_sha256 or ''),'PINNED_ADMISSION_REQUIRED')
    stage = A.PARENT/plan['release']['sha256'];A.private_dir(stage)
    need(A.read(stage/'plan.json',private=True) == canonical(plan),'STAGED_PLAN_CHANGED')
    admission_raw = A.read(stage/'admission.json',private=True)
    need(sha(admission_raw) == admission_sha256,'ADMISSION_CHANGED')
    created = A.parse(A.read(stage/'created.json',private=True))
    admission = validate_created_destination(created,admission_raw,plan['release']['sha256'])
    resources = {}
    ids = {**{'old-'+name:pin[0] for name,pin in A.BASE.items()},
           **{'new-'+name:pin['id'] for name,pin in admission['infrastructure'].items() if name != 'oracle-applied-ai-label'}}
    for name,identity in ids.items():
        item = A.inspect_container(identity);state = item['State']
        need(item['Id'] == identity,'RESOURCE_ID_CHANGED')
        resources[name] = {'id':identity,'name':item['Name'].lstrip('/'),'image':'sha256:'+item['Image'].removeprefix('sha256:'),
            'running':state['Running'],'status':state['Status'],'pid':state['Pid'],
            'started_at':state['StartedAt'],'finished_at':state['FinishedAt'],'exit_code':state['ExitCode']}
    markers = {}
    known = ('cutover-stopped.json','cutover-prepared.json','project-start-floor.json','public-release-intent.json',
             'public-release-complete.json','recover-prestart-intent.json','recover-prestart-complete.json',
             'paired-readiness.json','operator-startup.json')
    for name in known:
        path = stage/name
        if path.exists() or path.is_symlink():markers[name] = sha(A.read(path,private=True))
    return {'status':'OBSERVED_NOT_AUTHORIZED','scope':'fox-paired-cutover-readonly-status-v1',
        'release_sha256':plan['release']['sha256'],'admission_sha256':admission_sha256,'resources':resources,
        'services':{name:service_state(A,name,rootful=name == 'fox-https.service') for name in
            ('fox.service','forms2apex-mcp.service','fox-https.service','fox-product-verifier.service')},
        'retained_marker_sha256':markers,'automatic_replay_permitted':False,
        'next_action':'Reconcile the same phase and exact resources; do not repeat stop, create, import or start blindly.'}


def execute_under_lock(context, capture_authority, *, plan_raw, plan_sha256, installation_reference,
                       phase, expected_source_sha256, apply=False, backup_operation=None,
                       backup_completion_sha256=None, restore_operation=None, restore_completion_sha256=None):
    """Genuine caller-held Windows leases; no callback/boolean substitutes."""
    need(apply is True and phase in ('stop','activate','release','recover') and SHA.fullmatch(expected_source_sha256 or ''),
         'EXPLICIT_REVIEWED_PHASE_REQUIRED')
    source = Path(__file__).read_bytes()
    need(sha(source) == expected_source_sha256 and sha(plan_raw) == plan_sha256,'CUTOVER_SOURCE_OR_PLAN_CHANGED')
    from qa.operator.preactivation_retirement import PreActivationRetirementContext
    need(type(context) is PreActivationRetirementContext,'REAL_PREACTIVATION_CONTEXT_REQUIRED')
    module = inspect.getmodule(type(capture_authority))
    need(module is not None and type(capture_authority) is getattr(module,'CaptureAuthority',None)
         and capture_authority.owner is context,'REAL_SNAPSHOT_AUTHORITY_REQUIRED')
    config = capture_authority.require_active()
    need(config['mode'] == 'pre-hosted-g' and sha(Path(module.__file__).read_bytes()) == config['source_sha256']['hosted_snapshot.py'],
         'SNAPSHOT_AUTHORITY_SOURCE_CHANGED')
    # The exact CaptureAuthority above owns this exact context and its
    # require_active() already validates the held C/F/G leases. Repeating
    # the expensive retained retry read here can consume the 30s window.
    if phase == 'stop':
        # baseline_authority performs the genuine fresh history read before
        # constructing this exact, source-measured capability. Do not repeat
        # that long Windows scan; require immediate use, then recheck actual
        # backend eligibility after TLS is held on the host.
        need(0 <= time.monotonic()-capture_authority.issued <= 30, 'FRESH_BASELINE_CAPTURE_AUTHORITY_REQUIRED')
    packet = {'schema_version':1,'scope':SCOPE,'phase':phase,'plan':json.loads(plan_raw),'plan_sha256':plan_sha256,
        'installation':installation_reference,'snapshot_configuration':base64.b64encode(capture_authority.raw).decode(),
        'snapshot_configuration_sha256':capture_authority.digest,'backup_operation':backup_operation,
        'backup_completion_sha256':backup_completion_sha256,'restore_operation':restore_operation,
        'restore_completion_sha256':restore_completion_sha256,'helper_sha256':expected_source_sha256}
    # Source is already root-reviewed and packet-pinned. It is never written
    # into the image/B source tree or supplied as an end-user control.
    loader = ("import base64,hashlib,json,pathlib,sys,types;p=json.load(sys.stdin);raw=base64.b64decode(p.pop('source'),validate=True)\n"
              "if hashlib.sha256(raw).hexdigest()!=p['helper_sha256']:raise RuntimeError('CUTOVER_SOURCE_CHANGED')\n"
              "m=types.ModuleType('leased_cutover');m.__file__=p.pop('helper_path');sys.modules[m.__name__]=m;"
              "exec(compile(raw,m.__file__,'exec'),m.__dict__);print(json.dumps(m.HostCutover(p).execute(),sort_keys=True))")
    helper_path = remote_helper_path(installation_reference['path'])
    payload = {**packet,'source':base64.b64encode(source).decode(),'helper_path':helper_path}
    # The host copy is intentionally required and hash-checked by HostCutover;
    # bootstrap/staging of this reviewed controller is a separate owner action.
    python = config['python']['path']
    raw = context.components.clean.run_process([*context.components.clean.SSH,
        shlex.quote(python)+' -I -B -c '+shlex.quote(loader)],data=canonical(payload),timeout=900)
    capture_authority.require_active()  # Also rechecks its actual owning context.
    result = json.loads(raw)
    need(result.get('status') == {'stop':'G_STOPPED_TLS_HELD','activate':'PROJECT_RUNNING_TLS_HELD',
         'recover':'G_AVAILABILITY_RECOVERED_OPERATOR_REMAINS_RETIRED','release':'PAIRED_SERVICE_ACTIVATED'}[phase]
         and result.get('automatic_replay_permitted') is False,'CUTOVER_RESULT_UNCONFIRMED_NO_REPLAY')
    return result


def execute_forward_under_lock(context, *, operation, plan_raw, plan_sha256, installation_reference,
        snapshot_configuration_raw, snapshot_configuration_sha256, backup_operation,
        backup_completion_sha256, restore_operation, restore_completion_sha256,
        parent_result_sha256, expected_source_sha256, apply=False, admin_value=None):
    """Fresh retired-history leases for a specific reconciled forward state.

    This never mints/reuses an expired snapshot capability and exposes no backup,
    stop, rename, converter restart or G rollback action. Host-side genuine
    archive/restore checks and the actual stage lock govern every continuation.
    """
    need(apply is True and operation in ('finish-activation','install-admin-reference','release','repair-verifier-setting','prepare-verifier-storage')
         and SHA.fullmatch(expected_source_sha256 or '') and SHA.fullmatch(parent_result_sha256 or ''),
         'EXPLICIT_FORWARD_CONTINUATION_REQUIRED')
    need((admin_value is None) if operation!='install-admin-reference' else
         (type(admin_value)is str and re.fullmatch(r'[A-Za-z0-9_!#%+.,:=?@^*-]{12,128}',admin_value)),
         'FORWARD_SECRET_BOUNDARY_INVALID')
    source=Path(__file__).read_bytes()
    need(sha(source)==expected_source_sha256 and sha(plan_raw)==plan_sha256
         and sha(snapshot_configuration_raw)==snapshot_configuration_sha256,
         'FORWARD_SOURCE_OR_CONFIGURATION_CHANGED')
    from qa.operator.preactivation_retirement import PreActivationRetirementContext
    need(type(context) is PreActivationRetirementContext,'REAL_FORWARD_WINDOWS_CONTEXT_REQUIRED')
    try:
        context.require_active()
        PreActivationRetirementContext._leases(context)  # Genuine fd leases, not an instance callback.
    except Exception:
        raise CutoverError('ACTUAL_RETIRED_HISTORY_LEASES_REQUIRED') from None
    config=json.loads(snapshot_configuration_raw)
    need(config.get('mode')=='pre-hosted-g' and config.get('operator_release_sha256')==context.release
         and config['runtime']['fox']==context.configuration['infrastructure']['fox']
         and config['runtime']['converter']==context.configuration['infrastructure']['forms2apex-mcp']
         and sha(context.source_files()['preactivation/preactivation_retirement.py'])==config['authority_source_sha256'],
         'FORWARD_RETIRED_SOURCE_BINDING_CHANGED')
    need(SHA.fullmatch(backup_completion_sha256 or '') and SHA.fullmatch(restore_completion_sha256 or ''),
         'EXACT_FORWARD_BACKUP_AND_RESTORE_REQUIRED')
    install=PurePosixPath(installation_reference['path'])
    need(install.is_absolute() and str(install)==installation_reference['path'] and '..' not in install.parts,
         'FORWARD_INSTALLATION_PATH_INVALID')
    helper_path=str(install.parent/('cutover_project_release-'+expected_source_sha256+'.py'))
    packet={'schema_version':1,'scope':SCOPE,'phase':'release' if operation in ('release','repair-verifier-setting','prepare-verifier-storage') else 'activate',
        'plan':json.loads(plan_raw),'plan_sha256':plan_sha256,'installation':installation_reference,
        'snapshot_configuration':base64.b64encode(snapshot_configuration_raw).decode(),
        'snapshot_configuration_sha256':snapshot_configuration_sha256,'backup_operation':backup_operation,
        'backup_completion_sha256':backup_completion_sha256,'restore_operation':restore_operation,
        'restore_completion_sha256':restore_completion_sha256,'helper_sha256':expected_source_sha256}
    envelope={'operation':operation,'packet':packet,'helper_path':helper_path,
        'parent_result_sha256':parent_result_sha256,'admin_value':admin_value}
    loader=r'''
import hashlib,importlib.util,json,pathlib,re,sys
value=json.load(sys.stdin);p=value['packet'];path=pathlib.Path(value['helper_path']);raw=path.read_bytes()
if hashlib.sha256(raw).hexdigest()!=p['helper_sha256']:raise RuntimeError('FORWARD_HOST_SOURCE_CHANGED')
spec=importlib.util.spec_from_file_location('leased_forward_controller',path)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(raw,str(path),'exec'),m.__dict__)
try:
 h=m.HostCutover(p);op=value['operation']
 if op=='finish-activation':result=h.resume_after_converter_start()
 elif op=='install-admin-reference':result=h.install_forward_admin_reference(value['admin_value'])
 elif op=='release':result=h.execute()
 elif op=='repair-verifier-setting':result=h.resume_failed_verifier_setting()
 elif op=='prepare-verifier-storage':result=h.resume_failed_verifier_storage()
 else:raise RuntimeError('FORWARD_OPERATION_INVALID')
except BaseException as error:
 code=str(error)
 result={'status':'ATTENTION','code':code if re.fullmatch('[A-Z0-9_]{1,160}',code) else 'FORWARD_INTERNAL_FAILURE_DETAILS_WITHHELD',
  'automatic_replay_permitted':False,'next_action':'RECONCILE_SAME_FORWARD_STEP_NO_REPLAY'}
print(json.dumps(result,sort_keys=True))
'''
    wire=base64.b64encode(loader.encode())+b'\n'+canonical(envelope)
    raw=context.components.clean.run_process([*context.components.clean.SSH,config['python']['path']+
        " -I -B -c 'import base64,sys;exec(base64.b64decode(sys.stdin.buffer.readline()))'"],data=wire,timeout=900)
    context.require_active();PreActivationRetirementContext._leases(context)
    result=json.loads(raw)
    expected={'finish-activation':'PROJECT_RUNNING_TLS_HELD','install-admin-reference':'PROTECTED_ADMIN_REFERENCE_INSTALLED',
              'release':'PAIRED_SERVICE_ACTIVATED','repair-verifier-setting':'PAIRED_SERVICE_ACTIVATED',
              'prepare-verifier-storage':'PAIRED_SERVICE_ACTIVATED'}[operation]
    if result.get('status')=='ATTENTION':
        code=result.get('code','')
        raise CutoverError(code if type(code)is str and re.fullmatch('[A-Z0-9_]{1,160}',code) else 'FORWARD_OUTCOME_UNCONFIRMED_NO_REPLAY')
    need(result.get('status')==expected and result.get('automatic_replay_permitted') is False,
         'FORWARD_OUTCOME_UNCONFIRMED_NO_REPLAY')
    return result


if __name__ == '__main__':
    raise SystemExit('Use the leased operator API; no direct service-action CLI is exposed.')
