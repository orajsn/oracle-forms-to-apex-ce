"""Forward-only JSN current-pair transition with retained original evidence.

The existing installation supplies its real source, operator lease and snapshot
authority. Fresh children inspect the new namespace. No old pump, G cutover,
model call, application import, live restore, deletion or automatic replay is
exposed. A failed attempt requires observation, not another apply.
"""
from __future__ import annotations
import argparse
import base64
from copy import deepcopy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import re
import shlex
import subprocess
import sys
import time

sys.dont_write_bytecode=True
SCOPE='fox-current-pair-transition-v1'
SCOPE_V2='fox-current-pair-transition-v2'
SHA=re.compile(r'[a-f0-9]{64}\Z')
PARENT=Path('/home/opc/.local/share/fox-project-transitions')
UNIT=Path('/home/opc/.config/systemd/user/fox-product-verifier.service')
REFS=('old_installation','new_installation','old_unit','new_unit','helper','support','readiness','recovery','snapshot')


def references(p):
    return REFS + (('snapshot_adapter',) if p['schema_version'] == 2 else ()) + (
        ('candidate_plan',) if p['schema_version'] == 2 and 'candidate_plan' in p else ())


class TransitionError(RuntimeError):pass


def need(value,code):
    if not value:raise TransitionError(code)


def cb(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def document(raw):
    def unique(rows):
        out={}
        for key,value in rows:
            need(key not in out,'DUPLICATE_JSON_KEY');out[key]=value
        return out
    try:return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except TransitionError:raise
    except Exception:raise TransitionError('INVALID_JSON_DOCUMENT') from None


def absolute(value):
    need(type(value)is str and len(value)<=1024 and '\\' not in value and not any(ord(x)<32 for x in value),'INVALID_ABSOLUTE_PATH')
    p=PurePosixPath(value)
    need(p.is_absolute() and str(p)==value and '..' not in p.parts,'INVALID_ABSOLUTE_PATH')
    return Path(value)


def plan_document(raw,expected):
    need(type(raw)is bytes and len(raw)<=1_000_000 and type(expected)is str and SHA.fullmatch(expected) and sha(raw)==expected,'EXACT_TRANSITION_PLAN_REQUIRED')
    p=document(raw)
    need(type(p)is dict and type(p.get('schema_version'))is int and p['schema_version'] in (1,2), 'TRANSITION_PLAN_INVALID')
    need(set(p)=={'schema_version','scope','controller_sha256',*references(p)}
        and p['scope']==(SCOPE if p['schema_version']==1 else SCOPE_V2)
        and cb(p)==raw and type(p['controller_sha256'])is str and SHA.fullmatch(p['controller_sha256']), 'TRANSITION_PLAN_INVALID')
    for key in references(p):
        ref=p[key];need(type(ref)is dict and set(ref)=={'path','sha256'} and type(ref['sha256'])is str and SHA.fullmatch(ref['sha256']),'REFERENCE_INVALID')
        absolute(ref['path'])
    need(p['old_installation']!=p['new_installation'] and p['old_unit']['path']==UNIT.as_posix()
        and p['new_unit']['path']!=UNIT.as_posix(),'DISTINCT_INSTALLATION_AND_UNIT_REQUIRED')
    return p


def initial_read(path):
    import stat
    path=absolute(str(path))
    for part in (path,*path.parents):
        st=part.lstat()
        need(not stat.S_ISLNK(st.st_mode) and st.st_uid in (0,os.geteuid()),'UNTRUSTED_BOOTSTRAP_PATH')
        need(not stat.S_IMODE(st.st_mode)&0o022 or (part!=path and stat.S_ISDIR(st.st_mode)
            and st.st_uid==0 and st.st_mode&stat.S_ISVTX),'WRITABLE_BOOTSTRAP_PATH')
    st=path.stat();need(path.resolve()==path and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=16_000_000,'BOOTSTRAP_FILE_INVALID')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:raw=stream.read(16_000_001)
    need(len(raw)==st.st_size and path.stat().st_mtime_ns==st.st_mtime_ns,'BOOTSTRAP_FILE_CHANGED')
    return raw


def load(name,ref):
    path=absolute(ref['path']);raw=initial_read(path);need(sha(raw)==ref['sha256'],'HELPER_SOURCE_CHANGED')
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m


def snapshot_adapter(p,baseline,installation,inventory):
    """Explicit v2 adapter from the new measured bundle, never patch old source."""
    if p['schema_version']==1:
        return baseline
    ref=p['snapshot_adapter'];relative='qa/operator/hosted_snapshot.py'
    need(ref['path']==str(PurePosixPath(installation['layout']['release_root'])/relative)
        and inventory['files'].get(relative)==ref['sha256'], 'SNAPSHOT_ADAPTER_OUTSIDE_NEW_BUNDLE')
    return load('qa.operator._current_transition_snapshot',ref)


def validate_profile_access_labels(old_label,new_label,old_process,new_process):
    """Installation metadata, not source bytes or permission broadening."""
    if old_label is None and new_label is None and not old_process and not new_process:return
    need(type(old_label)is str and ':object_r:container_file_t:' in old_label
        and new_label==old_label and old_process==new_process,'PREPARE_NEW_PROFILE_ACCESS_LABELS_FIRST')


def validate_candidate_plan_reference(p,path,raw,candidate):
    """New queue authority must be in the reviewed transition digest as well.

    Legacy transitions remain unchanged. An opt-in candidate is never authorized
    merely by hashing whichever configuration happens to be present on disk.
    """
    reference=p.get('candidate_plan')
    need('hosted_forms_queue' not in candidate or reference is not None,
         'EXPLICIT_CANDIDATE_PLAN_REFERENCE_REQUIRED')
    if reference is not None:
        need(reference=={'path':str(path),'sha256':sha(raw)},'CANDIDATE_PLAN_REFERENCE_CHANGED')


BACKEND=r'''
import base64,json,pathlib,sys,types
p=json.load(sys.stdin);sys.path[:0]=p['paths']
raw=base64.b64decode(p['source'],validate=True)
import hashlib
assert hashlib.sha256(raw).hexdigest()==p['sha256']
m=types.ModuleType('fox._transition_recovery');m.__package__='fox';sys.modules[m.__name__]=m
exec(compile(raw,'<measured-transition-reader>','exec'),m.__dict__)
store=m.VerificationRecovery(pathlib.Path(p['data'])/'fox.sqlite3',enabled=True)
with store._db(False) as db:
 db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
 ids=store._job_ids(db);eligibility={job:store._eligibility(db,job) for job in sorted(ids)}
 assert len(ids)<=10000 and all(v['blocks_admission'] is False for v in eligibility.values())
 closed={}
 if store._precheck_schema(db):
  for row in db.execute('SELECT assessment_raw FROM verification_precheck_failures'):
   a=m._load(row[0]);job=a['binding']['job_id'];store._closed_precheck(db,job)
   assert a['session'] not in closed
   closed[a['session']]={'job_id':job,'assessment_sha256':m.digest(row[0]),'retained_sha256':a['retained_sha256']}
 stages={}
 if hasattr(store,'_qa_stage_schema') and store._qa_stage_schema(db):
  for row in db.execute('SELECT assessment_raw FROM verification_qa_stage_failures'):
   a=m._load(row[0]);job=a['binding']['job_id'];store._closed_qa_stage(db,job)
   assert a['session'] not in stages and a['session'] not in closed
   stages[a['session']]={'job_id':job,'assessment_sha256':m.digest(row[0]),'retained_sha256':a['retained_sha256']}
 prewrite={}
 if hasattr(store,'_project_prewrite_schema') and store._project_prewrite_schema(db):
  for row in db.execute('SELECT assessment_raw FROM verification_project_prewrite_failures'):
   a=m._load(row[0]);job=a['binding']['job_id'];store._closed_project_prewrite(db,job)
   assert a['session'] not in prewrite and a['session'] not in closed and a['session'] not in stages
   prewrite[a['session']]={'job_id':job,'assessment_sha256':m.digest(row[0]),'retained_sha256':a['retained_sha256']}
 print(json.dumps({'jobs':sorted(ids),'eligibility':eligibility,'outcomes':store._precheck_original_rows(db),'closed_prechecks':closed,'closed_qa_stages':stages,'closed_project_prewrite':prewrite},sort_keys=True))
'''


def retained_failure_sessions(value):
    """Read separately validated failure families, never infer a successful seal."""
    need(type(value)is dict,'FAILURE_FAMILY_SNAPSHOT_INVALID')
    result={}
    for key,family,count in (('closed_prechecks','clean_check',7),('closed_qa_stages','qa_stage',17),('closed_project_prewrite','project_prewrite',22)):
        entries=value.get(key,{}) if key=='closed_project_prewrite' else value.get(key)
        need(type(entries)is dict,'FAILURE_FAMILY_SNAPSHOT_INVALID')
        for session,row in entries.items():
            need(type(session)is str and re.fullmatch(r'session-[a-f0-9]{24}',session)
                and session not in result and type(row)is dict
                and set(row)=={'job_id','assessment_sha256','retained_sha256'}
                and type(row['job_id'])is str and re.fullmatch(r'fox-[a-f0-9]{20}',row['job_id'])
                and type(row['assessment_sha256'])is str and re.fullmatch(r'[a-f0-9]{64}',row['assessment_sha256'])
                and type(row['retained_sha256'])is dict and len(row['retained_sha256'])==count
                and all(type(name)is str and re.fullmatch(r'[a-z0-9.-]+\.json',name)
                    and type(digest)is str and re.fullmatch(r'[a-f0-9]{64}',digest)
                    for name,digest in row['retained_sha256'].items()),'FAILURE_FAMILY_HISTORY_INVALID')
            result[session]={**row,'failure_family':family}
    return result


NEW_PROBE=r'''
import hashlib,importlib.util,json,pathlib,sys,time
p=json.load(sys.stdin)
def load(name,ref):
 path=pathlib.Path(ref['path']);raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==ref['sha256']
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m
 exec(compile(raw,str(path),'exec'),m.__dict__);return m
A=load('new_transition_helper',p['helper'])
i=A.parse(A.read(pathlib.Path(p['installation']['path']),private=True))
root,runtime,bridge,verifier=A.source_namespace(i['layout']['release_root'],i['layout']['inventory']['sha256'])
from qa.operator import hosted_service as service
admission=service.HostedAdmission(p['installation']['path'],expected_sha256=p['installation']['sha256'])
admission.archive.read();admission.provider.oci_scope(require_database_available=True)
if p['mode']=='structural':result={'status':'STRUCTURAL_NOT_STARTUP_ADMITTED','release_sha256':admission.release}
elif p['mode']=='admission':
 result=admission.check();assert result['status']=='CHECKED_NOT_STARTED'
 secret=admission.provider.admin_secret();del secret
elif p['mode']=='readiness':
 ready=load('new_transition_readiness',p['readiness'])
 plan=A.parse(A.read(pathlib.Path(p['candidate_plan']['path']),private=True))
 assert A.sha(A.canonical(plan))==p['candidate_plan']['sha256']
 d=A.parse(admission.reference_raw['admission'])['infrastructure']
 result=ready.run(A,plan,admission.manifest,{'fox':d['fox'],'converter':d['forms2apex-mcp']})
 assert result['status']=='READ_ONLY_CONNECTIVITY_CONFIRMED'
elif p['mode']=='idle':
 journal=verifier.PrivateJournal(admission.release);deadline=time.monotonic()+60;result=None
 while time.monotonic()<deadline:
  if journal.root.exists():
   for directory in sorted(journal.root.glob('session-*')):
    assert not (directory/'attention.json').exists(),'NEW_VERIFIER_ATTENTION'
    if not (directory/'p0001-claim.complete.json').exists():continue
    header=journal.read(directory,'session.json')
    assert header['release_sha256']==admission.release and header['startup_authorized'] is True
    assert header['bounds']==admission.document['bounds']
    intent=journal.raw(directory,'p0001-claim.intent.json');outcome=journal.read(directory,'p0001-claim.complete.json')
    assert json.loads(intent)=={'scope':'fox-product-verifier-step-v1','release_sha256':admission.release,'step':'p0001-claim','binding_sha256':None}
    assert outcome['result']=={'status':'IDLE'} and outcome['intent_sha256']==hashlib.sha256(intent).hexdigest()
    if (directory/'complete.json').exists():
     complete=journal.read(directory,'complete.json')
     assert complete['status']=='SESSION_COMPLETE' and complete['completed_jobs']==[]
     journal._check_seal(directory,complete)
    result={'status':'GENUINE_NEW_VERIFIER_IDLE_CLAIM','session':directory.name,'claim_complete_sha256':hashlib.sha256(journal.raw(directory,'p0001-claim.complete.json')).hexdigest(),'release_sha256':admission.release,'batch_completion_claimed':False}
    break
  if result:break
  time.sleep(1)
 assert result is not None,'NO_NEW_VERIFIER_IDLE_WITNESS'
 assert admission.check()['status']=='CHECKED_NOT_STARTED'
else:raise RuntimeError('UNKNOWN_READ_ONLY_PROBE')
print(json.dumps(result,sort_keys=True))
'''


class Transition:
    def __init__(self,p,*,status=False):
        self.p=p;self.digest=sha(cb(p));self.A=A=load('current_transition_helpers',p['helper'])
        self.M=M=load('current_transition_support',p['support']);A.host_identity()
        need(sha(initial_read(Path(__file__).resolve()))==p['controller_sha256'],'TRANSITION_SOURCE_CHANGED')
        for key in references(p):
            observed=sha(A.read(absolute(p[key]['path']),private=key not in ('helper','support','readiness','recovery')))
            need(observed in (p['old_unit']['sha256'],p['new_unit']['sha256']) if status and key=='old_unit'
                 else observed==p[key]['sha256'],'PINNED_INPUT_CHANGED')
        old=document(A.read(absolute(p['old_installation']['path']),private=True))
        old_root=absolute(old['layout']['release_root']);old_inventory=A.read(absolute(old['layout']['inventory']['path']),private=True)
        need(sha(old_inventory)==old['layout']['inventory']['sha256'] and A.read(old_root.parent/'source-inventory.json',private=True)==old_inventory,'OLD_SOURCE_INVENTORY_CHANGED')
        if not status:
            argv=shlex.split(next(line.split('=',1)[1] for line in A.read(UNIT,private=True).decode().splitlines() if line.startswith('ExecStart=')))
            need(argv[-5:]==['--installation',p['old_installation']['path'],'--installation-sha256',p['old_installation']['sha256'],'--apply']
                and str(old_root/'qa/operator/hosted_service.py') in argv,'OLD_UNIT_INSTALLATION_CHANGED')
        A.source_namespace(old_root,old['layout']['inventory']['sha256'])
        self.service=service=importlib.import_module('qa.operator.hosted_service')
        self.old=service.HostedAdmission(p['old_installation']['path'],expected_sha256=p['old_installation']['sha256'])
        self.old.archive.read();self.scope()
        self.snapshot_raw=A.read(absolute(p['snapshot']['path']),private=True)
        self.new_raw=A.read(absolute(p['new_installation']['path']),private=True)
        self.new_i=service.installation_document(self.new_raw,expected_sha256=p['new_installation']['sha256'])
        self.new_refs={key:A.read(absolute(self.new_i[key]['path']),private=True) for key in ('provider','release','admission')}
        for key,data in self.new_refs.items():need(sha(data)==self.new_i[key]['sha256'],'NEW_REFERENCE_CHANGED')
        self.cfg=document(self.new_refs['provider']);self.release=document(self.new_refs['release']);self.R=self.new_i['release']['sha256']
        self.pins=document(self.new_refs['admission'])['infrastructure'];self.old_pins=document(self.old.reference_raw['admission'])['infrastructure']
        need(self.R!=self.old.release and all(self.pins[n]['image']!=self.old_pins[n]['image'] for n in ('fox','forms2apex-mcp')),'DISTINCT_CURRENT_RELEASE_REQUIRED')
        inventory=A.read(absolute(self.new_i['layout']['inventory']['path']),private=True)
        need(sha(inventory)==self.new_i['layout']['inventory']['sha256'],'NEW_SOURCE_INVENTORY_CHANGED')
        service.verify_inventory(absolute(self.new_i['layout']['release_root']),inventory)
        measured=document(inventory)
        self.S=snapshot_adapter(p,importlib.import_module('qa.operator.hosted_snapshot'),self.new_i,measured)
        self.snapshot=self.S.configuration_document(self.snapshot_raw,p['snapshot']['sha256'])
        if p['schema_version']==2:
            need(self.snapshot['schema_version']==2 and self.snapshot['source_sha256']['hosted_snapshot.py']==p['snapshot_adapter']['sha256']
                and self.snapshot['source_sha256']['snapshot.py']==measured['files'].get('qa/operator/snapshot.py'),
                'SNAPSHOT_ADAPTER_SOURCE_BINDING_CHANGED')
        need(self.snapshot['mode']=='hosted' and self.snapshot['operator_release_sha256']==self.old.release
            and self.snapshot['provider_configuration_sha256']==self.old.document['provider']['sha256']
            and self.snapshot['runtime']['fox']==self.old_pins['fox']
            and self.snapshot['runtime']['converter']==self.old_pins['forms2apex-mcp'], 'CURRENT_SNAPSHOT_BINDING_CHANGED')
        need(p['recovery']['path']==str(absolute(self.new_i['layout']['release_root'])/'fox/fox/verification_recovery.py')
            and document(inventory)['files']['fox/fox/verification_recovery.py']==p['recovery']['sha256'],'UNBOUND_RECOVERY_READER')
        self.candidate_path=absolute(self.new_i['provider']['path']).parent/'activation-plan.json'
        raw=A.read(self.candidate_path,private=True);self.candidate_plan=A.plan_document(raw,sha(raw))
        validate_candidate_plan_reference(p,self.candidate_path,raw,self.candidate_plan)
        need(self.candidate_plan['current_installation']==p['old_installation'] and self.candidate_plan['release']==self.new_i['release']
            and self.candidate_plan['provider']==self.new_i['provider'] and self.candidate_plan['helper_sha256']==p['helper']['sha256'],'NEW_CANDIDATE_PLAN_CHANGED')
        self.root=PARENT/self.R;self.stage=self.root
        self.created={'candidates':{'fox':self.pins['fox'],'converter':self.pins['forms2apex-mcp']}}
        self.retained={'fox':'fox-pre-upgrade-'+self.R[:16],'converter':'forms2apex-pre-upgrade-'+self.R[:16]}

    def scope(self):
        self.A.host_identity()
        for path,expected in self.A.UNITS.values():need(sha(self.A.read(Path(path)))==expected,'EXISTING_SERVICE_UNIT_CHANGED')
        return self.old.provider.oci_scope(require_database_available=True)

    def record(self,name,value):self.A.create_file(self.root/name,cb(value))

    def effect(self,name,argv):
        self.scope();return self.A.create_once(self.root,name,argv,self.digest)

    def child(self,label,mode):
        packet={'mode':mode,'helper':self.p['helper'],'installation':self.p['new_installation'],'readiness':self.p['readiness'],
            'candidate_plan':{'path':str(self.candidate_path),'sha256':sha(self.A.read(self.candidate_path,private=True))}}
        source=base64.b64encode(NEW_PROBE.encode()).decode()
        loader="import base64,json,subprocess,sys;data=json.load(sys.stdin);r=subprocess.run([sys.executable,'-I','-B','-c',base64.b64decode(data['source']).decode()],input=json.dumps(data['packet']).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600);sys.stdout.buffer.write(r.stdout);sys.stderr.buffer.write(r.stderr);raise SystemExit(r.returncode)"
        # The durable launcher reads its private input file, never source or
        # credential bytes from argv. It observes the actual original child exit.
        input_path=self.root/(label+'-input.private.json');self.A.create_file(input_path,cb({'source':source,'packet':packet}))
        program="import pathlib,sys;sys.stdin=open(sys.argv[1]);"+loader
        return document(self.effect(label,[self.cfg['python']['path'],'-I','-B','-c',program,str(input_path)]))

    def data(self,*,stopped=False,new=False):
        A=self.A;root=Path(self.old.document['layout']['release_root'])
        packet={'source':base64.b64encode(A.read(absolute(self.p['recovery']['path']))).decode(),'sha256':self.p['recovery']['sha256'],
            'paths':[str(root/'fox'),str(root/'converter'),str(root)] if stopped else ['/app'],'data':'/home/opc/fox/data' if stopped else '/data'}
        cid=self.pins['fox']['id'] if new else self.old_pins['fox']['id']
        argv=['/usr/bin/podman','unshare',self.old.provider.configuration['python']['path']] if stopped else ['/usr/bin/podman','exec','-i',cid,'/usr/local/bin/python']
        r=subprocess.run(argv+['-I','-B','-c',BACKEND],input=cb(packet),capture_output=True,timeout=120)
        need(r.returncode==0 and len(r.stdout)<=1_000_000,'GLOBAL_IDLE_OR_HISTORY_UNCONFIRMED')
        value=document(r.stdout);journal=self.service.product.PrivateJournal(self.old.release)
        pending=journal.pending();failures=retained_failure_sessions(value)
        for directory in pending:
            need(directory.name in failures,'UNCLOSED_OLD_SESSION')
            expected=failures[directory.name]['retained_sha256']
            actual={x.name:sha(A.read(x,private=True)) for x in directory.iterdir()}
            need(actual==expected,'OLD_FAILED_TRANSCRIPT_CHANGED')
        files={x.relative_to(journal.root).as_posix():sha(A.read(x,private=True)) for x in journal.root.rglob('*') if x.is_file()}
        return {**value,'old_journal_inventory':files}

    def check_container(self,pin,name,signature,*,running):
        item=self.A.inspect_container(pin['id'])
        need(item['Id']==pin['id'] and item['Name'].lstrip('/')==name and item['Image'].removeprefix('sha256:')==pin['image'][7:]
            and item['State']['Running'] is running and self.M.configuration_matches(self.A,item,signature),'EXACT_CONTAINER_STATE_CHANGED')
        need(type(item['State']['Pid'])is int and (item['State']['Pid']>0 if running else item['State']['Pid']==0),'CONTAINER_PROCESS_STATE_CHANGED')
        return item

    def health(self):
        import urllib.request
        with urllib.request.urlopen('http://127.0.0.1:8100/api/health',timeout=5) as r:value=json.loads(r.read(65537))
        need(value.get('status')=='ok' and value.get('product')=='FOX' and value.get('worker',{}).get('healthy') is True
            and value['worker']['state'] in ('idle','polling'),'FOX_WORKER_NOT_IDLE_HEALTHY')
        return value

    def preflight(self):
        A=self.A;self.old.preflight();self.scope();self.health()
        need(sha(A.read(UNIT,private=True))==self.p['old_unit']['sha256'],'OLD_UNIT_CHANGED')
        old={n:A.inspect_container(n) for n in ('fox','forms2apex-mcp','oracle-applied-ai-label')}
        for name,pin in self.old_pins.items():need(old[name]['Id']==pin['id'] and old[name]['State']['Running'] is True,'CURRENT_PAIR_CHANGED')
        self.M.validate_snapshot_bindings(A,self.snapshot,old)
        tls=self.S._inspect(self.snapshot['runtime']['tls']['id'],True)
        need(tls['Name'].lstrip('/')=='fox-https' and tls['Image'].removeprefix('sha256:')==self.snapshot['runtime']['tls']['image'][7:]
            and tls['State']['Running'] is True and tls['State']['Pid']>0,'CURRENT_TLS_CHANGED')
        profile=document(A.read(absolute(self.candidate_plan['bundle_root'])/'deployment/project-opaf-profile-v2.json'))
        A.validate_hosted_queue(self.candidate_plan,self.cfg['python']['path'])
        signatures={'old':{},'new':{}}
        for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
            signatures['old'][role]=self.M.configuration_signature(A,old[name])
            candidate=A.inspect_container(self.pins[name]['id']);self.M.require_never_started(candidate)
            env=A.new_environment(role,old[name],self.R,profile,
                hosted_forms_queue=self.candidate_plan.get('hosted_forms_queue'))
            profiles={'fox':A.mount_map(old['fox'])['/run/fox-native/profile.json'][0],
                'converter':A.mount_map(old['forms2apex-mcp'])['/run/fox-target/profile.json'][0]}
            _,mounts=A.candidate_argv(role,old[name],self.candidate_plan,self.release,self.root,baseline_profiles=profiles)
            destination='/run/fox-native/profile.json' if role=='fox' else '/run/fox-target/profile.json'
            def label(path):
                import errno
                try:return os.getxattr(path,'security.selinux').decode().strip('\0')
                except OSError as error:
                    if error.errno in (errno.ENODATA,errno.ENOTSUP):return None
                    raise
            validate_profile_access_labels(label(profiles[role]),label(mounts[destination][0]),
                old[name].get('ProcessLabel'),candidate.get('ProcessLabel'))
            A.check_candidate(candidate,role,self.candidate_plan,self.release,env,mounts,baseline_item=old[name])
            signatures['new'][role]=self.M.configuration_signature(A,candidate)
        need(not set(self.retained.values())&set(A.command(['/usr/bin/podman','ps','-a','--format','{{.Names}}']).decode().splitlines()),'RETAINED_NAMES_ALREADY_EXIST')
        state=self.M.service_state(A,UNIT.name);need(state['MainPID']=='0' and state['ActiveState'] in ('failed','inactive'),'OLD_VERIFIER_NOT_STOPPED')
        need(A.command(['/usr/bin/systemctl','--user','is-enabled',UNIT.name]).strip()==b'enabled','EXISTING_VERIFIER_ENABLEMENT_CHANGED')
        need(not (Path(self.cfg['state_root'])/'product-verifier'/self.R[:16]).exists(),'NEW_VERIFIER_ALREADY_HAS_STATE')
        self.M.verify_service_unit(A,absolute(self.p['new_unit']['path']))
        measurement=self.S.measure(self.snapshot_raw,expected_sha256=self.p['snapshot']['sha256'])
        need(measurement['fits_current_limits'] is True,'BACKUP_CAPACITY_GATE_FAILED')
        return old,signatures,state,measurement

    def apply(self):
        A=self.A;old,signatures,old_verifier,measurement=self.preflight()
        journal=self.service.product.PrivateJournal(self.old.release)
        with journal.lock(create=False) as lease:
            self.old.preflight();self.scope();before=self.data()
            authority=self.S.hosted_authority(lease,self.snapshot_raw,expected_sha256=self.p['snapshot']['sha256'],release_raw=self.old.reference_raw['release'])
            with A.held_stage(self.root,create=True):
                self.record('plan.json',self.p);self.record('before.private.json',old);self.record('boundaries.json',signatures)
                self.record('before-data.json',before);self.record('capacity.json',measurement)
                self.record('owner-process.json',{'pid':os.getpid(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'start_ticks':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])})
                self.record('old-verifier-state.json',old_verifier)
                A.create_file(self.root/'old-verifier.service',A.read(UNIT,private=True))
                for directory in journal.root.rglob('*'):
                    if directory.is_file():
                        target=self.root/'retained-old-journal'/directory.relative_to(journal.root)
                        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);A.create_file(target,A.read(directory,private=True))
                self.child('new-structure','structural')
                self.effect('stop-tls',['sudo','-n','/usr/bin/systemctl','stop','fox-https.service'])
                tls=self.S._inspect(self.snapshot['runtime']['tls']['id'],True)
                need(tls['State']['Running'] is False and tls['State']['Pid']==0,'TLS_NOT_HELD')
                need(self.data()==before,'OLD_DATA_CHANGED_DURING_DRAIN')
                for role,unit,name in (('fox','fox.service','fox'),('converter','forms2apex-mcp.service','forms2apex-mcp')):
                    self.effect('stop-'+role,['/usr/bin/systemctl','--user','stop',unit])
                    self.check_container(self.old_pins[name],name,signatures['old'][role],running=False)
                need(self.data(stopped=True)==before,'STOPPED_OLD_DATA_NOT_IDLE')
                self.S._host_guard(self.snapshot)
                self.record('old-current-producer-retained.json',{'status':'STOPPED_WITH_FAILED_VERIFICATION_RETAINED','old_release':self.old.release,
                    'journal_inventory':before['old_journal_inventory'],'failed_sessions':retained_failure_sessions(before),
                    'successful_completion_claimed':False,'automatic_replay_permitted':False})
                capture='upgrade-capture-'+self.R[:16];restore='upgrade-restore-'+self.R[:16]
                self.S.execute_under_lock(authority,action='capture',operation=capture,apply=True)
                captured=self.S.read_status(self.snapshot_raw,expected_sha256=self.p['snapshot']['sha256'],operation=capture)
                need(captured['status']=='COMPLETE','FULL_BACKUP_NOT_COMPLETE');self.record('capture.json',captured)
                self.S.execute_under_lock(authority,action='restore',operation=restore,apply=True,
                    backup=Path(self.snapshot['output_root'])/capture/'snapshot',backup_completion_sha256=captured['completion_sha256'])
                restored=self.S.read_status(self.snapshot_raw,expected_sha256=self.p['snapshot']['sha256'],operation=restore)
                need(restored['status']=='COMPLETE','ISOLATED_RESTORE_NOT_COMPLETE');self.record('restore.json',restored)
                need(self.data(stopped=True)==before,'OLD_STATE_CHANGED_DURING_BACKUP')
                for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
                    self.effect('retain-'+role,['/usr/bin/podman','rename',self.old_pins[name]['id'],self.retained[role]])
                    self.check_container(self.old_pins[name],self.retained[role],signatures['old'][role],running=False)
                    self.effect('assign-'+role,['/usr/bin/podman','rename',self.pins[name]['id'],name])
                    self.check_container(self.pins[name],name,signatures['new'][role],running=False)
                self.record('new-start-floor.json',{'release':self.R,'old_verifier_replay_permitted':False,'backup':captured['completion_sha256']})
                for role,name,unit in (('converter','forms2apex-mcp','forms2apex-mcp.service'),('fox','fox','fox.service')):
                    self.effect('start-'+role,['/usr/bin/systemctl','--user','start',unit])
                    self.M.HostCutover.await_started(self,role,name,signatures['new'][role])
                self.M.HostCutover.await_fox_health(self);self.health()
                need(self.data(new=True)==before,'NEW_RUNTIME_CHANGED_RETAINED_OUTCOMES')
                self.record('new-admission.json',self.child('new-admission','admission'))
                self.record('readiness.json',self.child('new-readiness','readiness'))
                old_unit=A.read(UNIT,private=True);need(sha(old_unit)==self.p['old_unit']['sha256'] and self.M.service_state(A,UNIT.name)['MainPID']=='0','OLD_VERIFIER_CHANGED')
                target=UNIT.with_name('fox-product-verifier.upgrade-'+self.R[:16]+'.service')
                unit=A.read(absolute(self.p['new_unit']['path']),private=True);A.create_file(target,unit)
                self.M.verify_service_unit(A,target)
                self.scope();need(A.read(UNIT,private=True)==old_unit,'OLD_UNIT_CHANGED_BEFORE_REPLACEMENT')
                self.record('unit-replace-intent.json',{'old_sha256':sha(old_unit),'new_sha256':sha(unit),'new_installation':self.p['new_installation']})
                os.replace(target,UNIT);A.sync(UNIT.parent)
                self.effect('verifier-reload',['/usr/bin/systemctl','--user','daemon-reload'])
                self.effect('verifier-start',['/usr/bin/systemctl','--user','start',UNIT.name])
                identity=self.operator_identity();witness=self.child('new-first-idle','idle')
                need(self.operator_identity()==identity,'NEW_OPERATOR_PROCESS_CHANGED')
                self.record('operator-startup.json',{'identity':identity,'witness':witness})
                need(self.data(new=True)==before,'OUTCOMES_CHANGED_BEFORE_PUBLIC_RELEASE')
                for role,name in (('fox','fox'),('converter','forms2apex-mcp')):
                    retained=self.check_container(self.old_pins[name],self.retained[role],signatures['old'][role],running=False)
                    need(retained['State']['StartedAt']==old[name]['State']['StartedAt'],'OLD_CONTAINER_RESTARTED')
                self.effect('release-tls',['sudo','-n','/usr/bin/systemctl','start','fox-https.service'])
                health=self.M.public_health();need(self.operator_identity()==identity,'OPERATOR_CHANGED_DURING_RELEASE')
                result={'status':'CURRENT_PAIR_FORWARD_UPGRADE_ACTIVATED','old_release':self.old.release,'new_release':self.R,
                    'installation_sha256':self.p['new_installation']['sha256'],'public_health':health,'operator_first_idle':witness,
                    'old_outcomes_preserved':True,'old_failed_session_replayed':False,'model_invoked':False,'application_generated':False,
                    'end_to_end_conversion_proven':False,'human_acceptance_recorded':False,'automatic_replay_permitted':False}
                self.record('complete.json',result);return result

    def inspect(self):
        _,_,_,measurement=self.preflight()
        journal=self.service.product.PrivateJournal(self.old.release)
        with journal.lock(create=False) as lease:
            state=self.data()
            authority=self.S.hosted_authority(lease,self.snapshot_raw,
                expected_sha256=self.p['snapshot']['sha256'],release_raw=self.old.reference_raw['release'])
            authority.require_active()
        return {'status':'CURRENT_TRANSITION_INSPECTED_NOT_APPLIED','new_release':self.R,
            'backup_capacity':measurement,'old_jobs_checked':len(state['jobs']),
            'old_journal_files_checked':len(state['old_journal_inventory']),
            'actual_old_lease_and_snapshot_authority_checked':True,'services_changed':False}

    def operator_identity(self):
        state=self.M.service_state(self.A,UNIT.name)
        need(state['LoadState']=='loaded' and state['ActiveState']=='active' and state['MainPID'].isdigit(),'NEW_VERIFIER_NOT_RUNNING')
        argv=[self.cfg['python']['path'],'-I','-B',str(Path(self.new_i['layout']['release_root'])/'qa/operator/hosted_service.py'),
            'run','--installation',self.p['new_installation']['path'],'--installation-sha256',self.p['new_installation']['sha256'],'--apply']
        return self.M.runtime_identity(int(state['MainPID']),self.cfg['python']['path'],argv)

    def status(self):
        if not self.root.exists():return {'status':'NOT_STARTED','automatic_replay_permitted':False}
        self.A.private_dir(self.root)
        if not (self.root/'plan.json').exists():
            return {'status':'PARTIAL_STAGE_REQUIRES_OBSERVATION','records':sorted(x.name for x in self.root.iterdir()),'automatic_replay_permitted':False}
        need(self.A.read(self.root/'plan.json',private=True)==cb(self.p),'RECORDED_TRANSITION_PLAN_CHANGED')
        result={'status':'OBSERVED_NOT_REPLAYED','records':sorted(x.name for x in self.root.iterdir()),'automatic_replay_permitted':False}
        if (self.root/'complete.json').exists():result['completion']=document(self.A.read(self.root/'complete.json',private=True))
        elif (self.root/'complete-after-idle-claim.json').exists():
            recovered=document(self.A.read(self.root/'complete-after-idle-claim.json',private=True))
            need(recovered.get('status')=='CURRENT_PAIR_FORWARD_UPGRADE_ACTIVATED_AFTER_OBSERVED_RECOVERY'
                and recovered.get('new_release')==self.R
                and recovered.get('installation_sha256')==self.p['new_installation']['sha256']
                and recovered.get('operator_first_idle_claim',{}).get('status')=='GENUINE_NEW_VERIFIER_IDLE_CLAIM'
                and recovered.get('batch_completion_claimed') is False,'RECOVERED_TRANSITION_RECORD_CHANGED')
            result['completion']=recovered
        owner=document(self.A.read(self.root/'owner-process.json',private=True));proc=Path('/proc')/str(owner['pid'])
        try:live=int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==owner['start_ticks'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==owner['boot_id']
        except FileNotFoundError:live=False
        result['original_process']='ORIGINAL_LIVE' if live else 'ORIGINAL_ABSENT_OR_PID_REUSED'
        result['services']={name:self.M.service_state(self.A,name,rootful=name=='fox-https.service') for name in ('fox.service','forms2apex-mcp.service','fox-https.service',UNIT.name)}
        return result


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('inspect','apply','status'))
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True);parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();p=plan_document(initial_read(absolute(args.plan)),args.plan_sha256)
    need((args.action=='apply') is args.apply,'EXPLICIT_TRANSITION_APPLY_REQUIRED')
    context=Transition(p,status=args.action=='status')
    if args.action=='apply':result=context.apply()
    elif args.action=='status':result=context.status()
    else:
        result=context.inspect()
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'TRANSITION_UNCONFIRMED_INSPECT_NO_REPLAY','code':str(error) if type(error)is TransitionError else 'TRANSITION_GUARD_FAILED','automatic_replay_permitted':False}));raise SystemExit(1)
