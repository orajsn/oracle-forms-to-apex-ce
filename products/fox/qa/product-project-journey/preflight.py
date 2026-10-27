"""Read-only preflight of the exact installed JSN service, before UI writes."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from journey_contracts import canonical, need, object_bytes, validate_plan, validate_preflight
from private_io import private

SSH_NOTICE = (b'** WARNING: connection is not using a post-quantum key exchange algorithm.\n'
    b'** This session may be vulnerable to "store now, decrypt later" attacks.\n'
    b'** The server may need to be upgraded. See https://openssh.com/pq.html\n')


def ssh_diagnostics_allowed(stderr):
    # Retain strict host-key checking and all SSH settings. Accept only this
    # measured client notice, never arbitrary stderr or a failed command.
    return type(stderr) is bytes and stderr.replace(b'\r\n',b'\n') in (b'',SSH_NOTICE)


SCOPE_RECEIPT = r'''
def scope_receipt(identity,target):
 need(type(identity) is dict and set(identity)=={'instance_id','database_id','compartment_id','region',
  'database_db_name','instance_state','database_state','observed_at_utc'},'OCI_SCOPE_RECEIPT_INVALID')
 need(all(identity[key]==target[key] for key in ('instance_id','database_id','compartment_id','region'))
  and identity['instance_state']=='RUNNING' and identity['database_state']=='AVAILABLE'
  and identity['database_db_name']=='JSNF2APEX','OCI_SCOPE_IDENTITY_CHANGED')
 return {'instance':{'id':identity['instance_id'],'compartment_id':identity['compartment_id'],'region':identity['region']},
  'database':{'id':identity['database_id'],'compartment_id':identity['compartment_id'],
   'lifecycle_state':identity['database_state'],'db_name':identity['database_db_name']}}
'''


HOST_PREFIX = r'''
import hashlib,json,os,pathlib,re,stat,subprocess,sys,urllib.request
from datetime import datetime,timezone
def need(ok,code):
 if not ok:raise RuntimeError(code)
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
packet=json.load(sys.stdin);dep=packet['deployment'];provider=dep['provider'];release=dep['release'];D=dep['admission']
need(os.geteuid()==1000,'EXISTING_OPC_REQUIRED')
q=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(q,timeout=10) as response:imds=json.loads(response.read(100001))
need(imds['id']=='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
 and imds['compartmentId']=='ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
 and imds['canonicalRegionName']=='us-ashburn-1','EXACT_JSN_REQUIRED')
B=pathlib.Path('/home/opc/.local/share/fox-project-builds')/dep['source_bundle_sha256']/'bundle'
need(provider['converter_root']==str(B/'converter'),'SOURCE_LOCATION_CHANGED')
need(B.resolve(strict=True)==B and all(not p.is_symlink() for p in (B,*B.parents)),'SOURCE_ROOT_LINK_FORBIDDEN')
expected=dep['inventory']['files'];actual={};total=0
directories={str(p) for name in expected for p in pathlib.PurePosixPath(name).parents if str(p)!='.'}
for path in B.rglob('*'):
 info=path.lstat();need(not stat.S_ISLNK(info.st_mode),'SOURCE_LINK_FORBIDDEN')
 name=path.relative_to(B).as_posix()
 if stat.S_ISDIR(info.st_mode):need(name in directories,'SOURCE_DIRECTORY_CHANGED')
 else:
  need(name in expected and stat.S_ISREG(info.st_mode) and 0<=info.st_size<=8000000,'SOURCE_MEMBER_INVALID')
  total+=info.st_size;need(total<=80000000,'SOURCE_COLLECTION_TOO_LARGE')
  need(info.st_uid==os.geteuid() and info.st_nlink==1 and not stat.S_IMODE(info.st_mode)&0o022,'SOURCE_OWNERSHIP_CHANGED')
  with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
   opened=os.fstat(stream.fileno());need((opened.st_dev,opened.st_ino,opened.st_size)==(info.st_dev,info.st_ino,info.st_size),'SOURCE_CHANGED_WHILE_OPENING')
   raw=stream.read(8000001);after=os.fstat(stream.fileno())
  need(len(raw)==info.st_size and (opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns),'SOURCE_CHANGED_DURING_READ')
  actual[name]=hashlib.sha256(raw).hexdigest()
need(actual==expected,'SOURCE_INVENTORY_CHANGED')
sys.path[:0]=[str(B),str(B/'fox'),str(B/'converter')]
def command(args,timeout=30):
 result=subprocess.run(args,capture_output=True,stdin=subprocess.DEVNULL,timeout=timeout)
 need(result.returncode==0 and len(result.stdout)<2000000,'READ_ONLY_HOST_PROBE_FAILED')
 return result.stdout
items=json.loads(command(['/usr/bin/podman','inspect','fox','forms2apex-mcp','oracle-applied-ai-label']))
containers={};fox=None
for item in items:
 name=item['Name'].lstrip('/')
 need(name in D['infrastructure'] and name not in containers and item['State']['Running'] is True,'CONTAINER_STATE_CHANGED')
 containers[name]={'id':item['Id'],'image':'sha256:'+item['Image'].split(':')[-1]}
 if name=='fox':fox=item
need(containers==D['infrastructure'],'DEPLOYED_CONTAINER_IDENTITY_CHANGED')
env=dict(line.split('=',1) for line in fox['Config']['Env'])
need(env.get('FOX_VERIFIER_RELEASE_SHA256')==dep['release_sha256'] and env.get('FOX_CONVERSION_PROFILE')=='native-project-v1'
 and env.get('FOX_VERIFICATION_ENABLED')=='1' and env.get('FOX_RUN_ADAPTER')=='embedded-opaf','FOX_RUNTIME_PROFILE_CHANGED')
need(not any(m['Destination']=='/app' or m['Destination'].startswith('/app/') for m in fox['Mounts']),'APPLICATION_SOURCE_MOUNT_FORBIDDEN')
'''

HOST = HOST_PREFIX + SCOPE_RECEIPT + r'''
unit='fox-product-verifier.service'
service=dict(line.split('=',1) for line in command(['/usr/bin/systemctl','--user','show',unit,'--property=ActiveState,SubState,MainPID']).decode().splitlines())
need(service['ActiveState']=='active' and service['SubState']=='running' and service['MainPID'].isdigit(),'OPERATOR_SERVICE_NOT_RUNNING')
pid=int(service['MainPID']);need(pid>1,'OPERATOR_PID_REQUIRED')
proc=pathlib.Path('/proc')/str(pid)
def process_identity():
 raw=(proc/'stat').read_text();parts=raw[raw.rfind(')')+2:].split()
 need(raw.startswith(str(pid)+' (') and parts[0] not in ('Z','X','T','t'),'OPERATOR_PROCESS_NOT_RUNNING')
 return {'exe':str((proc/'exe').resolve(strict=True)),'start_ticks':parts[19]}
before=process_identity();argv=(proc/'cmdline').read_bytes().split(b'\0');argv=[x.decode() for x in argv if x]
need(len(argv)==10 and argv[:5]==[provider['python']['path'],'-I','-B',str(B/'qa/operator/hosted_service.py'),'run']
 and argv[5]=='--installation' and argv[7]=='--installation-sha256' and argv[9]=='--apply'
 and before['exe']==provider['python']['path'],'OPERATOR_COMMAND_BINDING_CHANGED')
from qa.operator.hosted_service import HostedAdmission
admission=HostedAdmission(argv[6],expected_sha256=argv[8])
need(admission.release==dep['release_sha256'] and admission.provider.raw==canonical(provider)
 and admission.reference_raw['release']==canonical(release) and admission.reference_raw['admission']==canonical(D),
 'INSTALLED_CONFIGURATION_CHANGED')
checked=admission.check();need(checked['status']=='CHECKED_NOT_STARTED','EXISTING_WORK_REQUIRES_ATTENTION')
identity=admission.provider.oci_scope(require_database_available=True)
scope=scope_receipt(identity,provider['target_profile']['oci'])
read_code="""import json,sqlite3,sys\nfrom pathlib import Path\nsys.path.insert(0,'/app')\nfrom fox.verification_recovery import VerificationRecovery\np=Path('/data/fox.sqlite3');r=VerificationRecovery(p,enabled=True)\nwith sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as c:\n c.row_factory=sqlite3.Row;c.execute('PRAGMA query_only=ON');c.execute('BEGIN')\n count=c.execute(\"SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')\").fetchone()[0]\n allowed=r.admission_allowed(c)\nprint(json.dumps({'active_conversion_count':count,'admission_allowed':allowed}))\n"""
snapshot=json.loads(command(['/usr/bin/podman','exec',containers['fox']['id'],'python','-I','-B','-c',read_code],timeout=60))
need(snapshot=={'active_conversion_count':0,'admission_allowed':True},'EXISTING_WORK_REQUIRES_ATTENTION')
need(process_identity()==before,'OPERATOR_PROCESS_CHANGED_DURING_READ')
again=json.loads(command(['/usr/bin/podman','inspect','fox','forms2apex-mcp','oracle-applied-ai-label']))
need({v['Name'].lstrip('/'):{'id':v['Id'],'image':'sha256:'+v['Image'].split(':')[-1]} for v in again}==containers
 and all(v['State']['Running'] is True for v in again),'CONTAINERS_CHANGED_DURING_READ')
result={'schema_version':1,'scope':'fox-live-project-preflight-v1','observed_at_utc':datetime.now(timezone.utc).isoformat(),
 'source_bundle_sha256':dep['source_bundle_sha256'],'release_sha256':dep['release_sha256'],'provider_sha256':dep['provider_sha256'],
 'admission_sha256':dep['admission_sha256'],'images':release['images'],'containers':containers,
 'instance':scope['instance'],'database':scope['database'],
 'active_conversion_count':0,'application_profile':'native-project-v1',
 'operator_service':{'unit':unit,'pid':pid,'start_ticks':before['start_ticks'],'state':'running'}}
result['receipt_sha256']=hashlib.sha256(canonical(result)).hexdigest()
print(json.dumps(result,sort_keys=True))
'''

STATUS = HOST_PREFIX + r'''
request=packet['project'];need(set(request)=={'name','customer','description'} and request['name'].startswith('Synthetic FOX live-'),'SYNTHETIC_PROJECT_REQUIRED')
source=r"""
import hashlib,json,sqlite3,sys
from pathlib import Path
sys.path.insert(0,'/app')
from fox.technical_release import checked_release
from fox.source_history import selected_sources,selected_source_set_id
from fox.intake import inventory
p=json.load(sys.stdin);root=Path('/data')
with sqlite3.connect((root/'fox.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
 db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 rows=db.execute('SELECT id,name FROM projects WHERE name=? AND customer=? AND description=?',
  (p['name'],p['customer'],p['description'])).fetchall()
 if len(rows)>1:raise RuntimeError('PROJECT_IDENTITY_AMBIGUOUS')
 result={'project_found':bool(rows),'runs':[]}
 if rows:
  pid=rows[0]['id'];result.update(project_id=pid,project_name=rows[0]['name'],selected_source_set_id=selected_source_set_id(db,pid),
   current_source_hash=inventory(selected_sources(db,pid))['source_hash'])
  runs=db.execute('SELECT * FROM runs WHERE project=? ORDER BY created',(pid,)).fetchall()
  if len(runs)>25:raise RuntimeError('RUN_INVENTORY_BOUND')
  for row in runs:
   run=dict(row);item={key:run[key] for key in ('id','source_hash','state')}
   item['human_acceptance_count']=db.execute('SELECT COUNT(*) FROM acceptances WHERE run=?',(run['id'],)).fetchone()[0]
   if run['state'] in ('VERIFIED','ACCEPTED'):
    verified=checked_release(db,root,run)
    proof=db.execute('SELECT proof_sha256 FROM technical_verifications WHERE run=?',(run['id'],)).fetchone()
    if not verified or not proof:raise RuntimeError('PROJECT_PROOF_REQUIRED')
    item.update(technical_proof_sha256=proof[0],package_sha256=hashlib.sha256(verified['package']).hexdigest())
   result['runs'].append(item)
print(json.dumps(result,sort_keys=True))
"""
r=subprocess.run(['/usr/bin/podman','exec','-i',containers['fox']['id'],'python','-I','-B','-c',source],input=json.dumps(request).encode(),capture_output=True,timeout=90)
need(r.returncode==0 and not r.stderr.strip() and len(r.stdout)<100000,'READ_ONLY_JOURNEY_STATE_UNCONFIRMED')
again=json.loads(command(['/usr/bin/podman','inspect','fox','forms2apex-mcp','oracle-applied-ai-label']))
need({v['Name'].lstrip('/'):{'id':v['Id'],'image':'sha256:'+v['Image'].split(':')[-1]} for v in again}==containers
 and all(v['State']['Running'] is True for v in again),'CONTAINERS_CHANGED_DURING_READ')
after_fox=next(v for v in again if v['Name'].lstrip('/')=='fox');after_env=dict(x.split('=',1) for x in after_fox['Config']['Env'])
need(all(after_env.get(k)==env.get(k) for k in ('FOX_VERIFIER_RELEASE_SHA256','FOX_CONVERSION_PROFILE','FOX_VERIFICATION_ENABLED','FOX_RUN_ADAPTER')),
 'FOX_PROFILE_CHANGED_DURING_READ')
result={'schema_version':1,'scope':'fox-live-project-read-only-status-v1','read_only':True,
 'release_sha256':dep['release_sha256'],'observed_at_utc':datetime.now(timezone.utc).isoformat(),
 'saved_project':json.loads(r.stdout),'automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''

LAUNCHER = r'''
import base64,hashlib,json,os,pathlib,re,stat,subprocess,sys
p=json.load(sys.stdin);python=p['deployment']['provider']['python']
path=pathlib.Path(python['path'])
def need(ok,code):
 if not ok:raise RuntimeError(code)
need(os.geteuid()==1000 and re.fullmatch('/home/opc/.local/share/fox-host-python/[a-f0-9]{64}/venv/bin/python3.11',str(path)),'APPROVED_HOST_PYTHON_REQUIRED')
for part in (path,*path.parents):need(not part.is_symlink(),'PYTHON_LINK_FORBIDDEN')
info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_uid==1000 and info.st_nlink==1
 and hashlib.sha256(path.read_bytes()).hexdigest()==python['sha256'],'PYTHON_IDENTITY_CHANGED')
program=base64.b64decode(p.pop('program_base64'),validate=True)
need(hashlib.sha256(program).hexdigest()==p.pop('program_sha256'),'PREFLIGHT_PROGRAM_CHANGED')
env={'PATH':'/usr/bin:/bin','HOME':'/home/opc','USER':'opc','LOGNAME':'opc','XDG_RUNTIME_DIR':'/run/user/1000',
 'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}
r=subprocess.run([str(path),'-I','-B','-c',program.decode()],input=json.dumps(p).encode(),capture_output=True,timeout=330,env=env,cwd='/')
need(r.returncode==0 and not r.stderr.strip() and len(r.stdout)<65536,'PREFLIGHT_READ_UNCONFIRMED')
sys.stdout.buffer.write(r.stdout)
'''


def observe(plan, key_file, *, runner=subprocess.run):
    validate_plan(plan)
    key = private(Path(key_file).absolute())
    need(key.is_file() and not key.is_symlink() and key.resolve() == key, 'EXISTING_SSH_KEY_REFERENCE_REQUIRED')
    program = HOST.encode()
    packet = {'deployment': plan['deployment'], 'program_base64': base64.b64encode(program).decode(),
              'program_sha256': hashlib.sha256(program).hexdigest()}
    result = runner(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-i', str(key),
        'opc@129.213.189.48', '/usr/bin/python3.11 -I -B -c ' + shlex.quote(LAUNCHER)],
        input=canonical(packet), capture_output=True, timeout=360)
    need(result.returncode == 0 and ssh_diagnostics_allowed(result.stderr) and len(result.stdout) < 65536,
         'LIVE_PREFLIGHT_UNCONFIRMED_NO_UI_ACTION')
    return validate_preflight(object_bytes(result.stdout, maximum=65536), plan)


def inspect_journey(plan, key_file, *, runner=subprocess.run):
    """Read saved project/run state, even while its conversion is still active."""
    validate_plan(plan)
    key = private(Path(key_file).absolute())
    program = STATUS.encode()
    packet = {'deployment': plan['deployment'], 'project': plan['project'],
              'program_base64': base64.b64encode(program).decode(), 'program_sha256': hashlib.sha256(program).hexdigest()}
    result = runner(['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-i', str(key),
        'opc@129.213.189.48', '/usr/bin/python3.11 -I -B -c ' + shlex.quote(LAUNCHER)],
        input=canonical(packet), capture_output=True, timeout=360)
    need(result.returncode == 0 and ssh_diagnostics_allowed(result.stderr) and len(result.stdout) < 65536,
         'READ_ONLY_JOURNEY_STATE_UNCONFIRMED')
    value = object_bytes(result.stdout, maximum=65536)
    need(set(value) == {'schema_version', 'scope', 'read_only', 'release_sha256', 'observed_at_utc', 'saved_project', 'automatic_replay_permitted'}
         and value['schema_version'] == 1 and value['scope'] == 'fox-live-project-read-only-status-v1'
         and value['read_only'] is True and value['automatic_replay_permitted'] is False
         and value['release_sha256'] == plan['deployment']['release_sha256'], 'READ_ONLY_STATUS_BINDING_CHANGED')
    return value
