"""Actual emitted backend/isolated namespace and measured packaging contracts."""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'fox/tests'),str(ROOT/'fox'),str(ROOT),str(ROOT/'deployment/tests')]
from test_paused_stage_preservation import inert_case
from fox import paused_stage_preservation as inert, verification_queue as queue, verification_recovery as recovery
from test_current_pair_transition import M,S
from test_paired_release_build import p as packaging, inputs


def execute(source,payload,monkeypatch):
    output=io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys,'stdin',io.StringIO(json.dumps(payload)));patch.setattr(sys,'stdout',output)
        try:exec(compile(source,'<actual-local-transition-program>','exec'),{})
        except SystemExit as exc:assert exc.code==0
    return json.loads(output.getvalue())


def seed_production_queue(case):
    # Fixture setup only. Production emitted readers below remain unchanged.
    with sqlite3.connect(case.database) as db:
        for table in ('verification_retry_events','verification_retry_attempts','verification_queue'):
            db.execute('DROP TABLE '+table)
        queue.initialize_schema(db)
    fox=case.observe();case.baseline.update(fox)
    case.expected['baseline']=case.baseline;case.expected['baseline_sha256']=inert.hashed(case.baseline)
    case.packet.update(fox=fox,binding=case.expected['baseline_sha256'])


def test_actual_emitted_controller_backend_never_adopts_history(inert_case,monkeypatch):
    c=inert_case;seed_production_queue(c)
    before=c.database.read_bytes();raw=Path(recovery.__file__).read_bytes()
    core=Path(inert.__file__).read_bytes()
    payload={'paths':[str(ROOT/'fox')],'source':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest(),
             'data':str(c.root),'paired_preclaim':{c.job_id:{'readback':c.packet,'expected':c.expected}},
             'inert_release':'f'*64,
             'inert_source':{'sha256':hashlib.sha256(core).hexdigest(),'bytes':base64.b64encode(core).decode()}}
    # Ordinary eligibility would reject the deliberately unresolved fixture.
    monkeypatch.setattr(recovery.VerificationRecovery,'_eligibility',lambda *a:pytest.fail('No ordinary classifier'))
    result=execute(M.BACKEND,payload,monkeypatch)
    assert result['eligibility'][c.job_id]=={'blocks_admission':True,'retry_eligible':False,'recovery_state':inert.STATE}
    assert result['preservation'][c.job_id]['preserved']['closure_claimed'] is False
    assert c.database.read_bytes()==before
    payload['paired_preclaim'][c.job_id]['readback']['host']['blockers']=['unknown']
    with pytest.raises(RuntimeError):execute(M.BACKEND,payload,monkeypatch)


def test_controller_scope_is_explicit_and_uses_shared_collector():
    assert M.preservation_stage({'scope':inert.BASELINE_SCOPE})=='inert'
    with pytest.raises(M.TransitionError):M.preservation_stage({'scope':'guessed-paused'})
    import inspect
    source=inspect.getsource(M.Transition.inert_read)
    assert 'H.paired(' in source and 'lease.require_active(' in source and 'self.preclaim_profile(' in source
    assert "'FOX_VERIFICATION_ENABLED'" in source and 'stopped_writer' in source


def test_new_modules_enter_measured_bundle_without_converter_expansion(tmp_path):
    data=inputs();core=Path(inert.__file__).read_bytes()
    from qa.operator import paused_stage_host
    host=Path(paused_stage_host.__file__).read_bytes()
    data['files'].update({'fox/fox/paused_stage_preservation.py':core,'qa/operator/paused_stage_host.py':host})
    output=tmp_path/'candidate';result=packaging.materialize(**data,output_root=output)
    import tarfile
    with tarfile.open(output/'paired-source.tar') as archive:
        names=set(archive.getnames())
        assert 'bundle/fox/fox/paused_stage_preservation.py' in names
        assert 'bundle/qa/operator/paused_stage_host.py' in names
        assert 'build/fox/fox/paused_stage_preservation.py' in names
        assert not any(name.startswith('build/converter/') and 'paused_stage' in name for name in names)
        assert archive.extractfile('bundle/qa/operator/paused_stage_host.py').read()==host
    # Execute only the two frozen pure module bytes in isolated namespaces. No
    # imports resolve workspace validators; no runtime dependency is constructed.
    for name,raw in (('frozen_inert_core',core),('frozen_inert_host',host)):
        namespace={'__name__':name};exec(compile(raw,'<frozen-measured-module>','exec'),namespace)
        assert namespace['hashed']({'x':1})==inert.hashed({'x':1})
    import subprocess
    payload={name:base64.b64encode(raw).decode() for name,raw in (('inert_core',core),('inert_host',host))}
    program='''import base64,json,sys
assert not any('site-packages' in item for item in sys.path)
for name,encoded in json.load(sys.stdin).items():
 namespace={'__name__':name}
 exec(compile(base64.b64decode(encoded),'<isolated-frozen-module>','exec'),namespace)
 assert namespace['hashed']({'x':1})=='5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22'
print('ISOLATED_FROZEN_PURE_IMPORTS')
'''
    done=subprocess.run([sys.executable,'-I','-S','-B','-c',program],input=json.dumps(payload).encode(),
                        capture_output=True,timeout=30,check=False)
    assert done.returncode==0 and not done.stderr and done.stdout.strip()==b'ISOLATED_FROZEN_PURE_IMPORTS'


@pytest.fixture
def verifier_case(tmp_path,monkeypatch):
    """Model host metadata; retain real emitted probe + runtime_identity + journal checks."""
    from types import ModuleType,SimpleNamespace
    from qa.operator import product_verifier as product,paused_stage_host as host
    import qa.operator
    import os
    root=tmp_path/'installed';root.mkdir();python=root/'python';python.write_bytes(b'synthetic executable')
    unit=root/'verifier.service';unit.write_bytes(b'reviewed exact unit')
    release='1'*64;inventory='2'*64;pid=456;boot='01234567-89ab-cdef-0123-456789abcdef'
    state={'LoadState':'loaded','ActiveState':'active','SubState':'running','MainPID':str(pid),'FragmentPath':str(unit)}
    installation=root/'installation.json';installation.write_text(json.dumps({'layout':{'release_root':str(root),
        'inventory':{'sha256':inventory}},'release':{'sha256':release}}))
    argv=[str(python),'-I','-B',str(root/'qa/operator/hosted_service.py'),'run','--installation',str(installation),
          '--installation-sha256',hashlib.sha256(installation.read_bytes()).hexdigest(),'--apply']
    process={'ticks':90000,'argv':b'\0'.join(v.encode() for v in argv)+b'\0'}
    class Proc:
        def __init__(self,value):self.value=str(value)
        def __truediv__(self,other):return Proc(self.value+'/'+str(other))
        def read_text(self):
            if self.value=='/proc/sys/kernel/random/boot_id':return boot
            if self.value==f'/proc/{pid}/stat':return f'{pid} (python) '+ ' '.join(['S','1']+['0']*17+[str(process['ticks'])])
            raise FileNotFoundError(self.value)
        def read_bytes(self):
            if self.value==f'/proc/{pid}/cmdline':return process['argv']
            raise FileNotFoundError(self.value)
        def resolve(self,strict=False):
            if self.value==f'/proc/{pid}/exe':return python
            raise FileNotFoundError(self.value)
    original_path=Path
    monkeypatch.setattr(S,'Path',lambda value:Proc(value) if str(value).startswith('/proc') else original_path(value))
    original_text=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda path,*a,**k:'1000.0 0.0' if path.as_posix()=='/proc/uptime' else original_text(path,*a,**k))
    monkeypatch.setattr(os,'sysconf',lambda key:100,raising=False)
    bounds={'max_jobs':1,'max_polls':1,'max_seconds':30,'poll_seconds':1}
    journal=object.__new__(product.PrivateJournal);journal.release=release;journal.root=root/'journal';journal.root.mkdir()
    directory=journal.root/('session-'+'a'*24);directory.mkdir()
    monkeypatch.setattr(product.promotion,'private_inputs',lambda *a,**k:None)  # Windows ownership seam only.
    def save(name,value):
        (directory/name).write_bytes(product.C.canonical_bytes(value))
    save('session.json',{'scope':'fox-product-verifier-session-v1','release_sha256':release,
        'started_at_utc':(datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat(),
        'bounds':bounds,'startup_authorized':True})
    save('p0001-claim.intent.json',{'scope':'fox-product-verifier-step-v1','release_sha256':release,
        'step':'p0001-claim','binding_sha256':None})
    save('p0001-claim.complete.json',{'scope':'fox-product-verifier-step-result-v1','release_sha256':release,
        'intent_sha256':hashlib.sha256((directory/'p0001-claim.intent.json').read_bytes()).hexdigest(),'result':{'status':'IDLE'}})
    save('complete.json',{'status':'SESSION_COMPLETE','release_sha256':release,'completed_jobs':[],
                         'retained_sha256':journal._retained(directory)})
    product_model=SimpleNamespace(PrivateJournal=lambda value:journal)
    provider=SimpleNamespace(configuration={'python':{'path':str(python)}},oci_scope=lambda **k:{})
    admission=SimpleNamespace(source_root=root,provider=provider,release=release,document={'bounds':bounds},
                              archive=SimpleNamespace(read=lambda:{}),check=lambda:{'status':'CHECKED_NOT_STARTED'})
    fake_service=ModuleType('qa.operator.hosted_service');fake_service.HostedAdmission=lambda *a,**k:admission
    monkeypatch.setitem(sys.modules,'qa.operator.hosted_service',fake_service)
    monkeypatch.setattr(qa.operator,'hosted_service',fake_service,raising=False)
    helper=SimpleNamespace(read=lambda path,**kw:Path(path).read_bytes(),parse=json.loads,
        command=lambda args:b'DropInPaths=',source_namespace=lambda *a:(root,None,None,product_model))
    env=ModuleType('_inert_verifier_test_env');env.helper=helper
    env.service_state=lambda *a,**k:deepcopy(state);env.runtime_identity=S.runtime_identity
    monkeypatch.setitem(sys.modules,env.__name__,env)
    h=root/'helper.py';h.write_text('from _inert_verifier_test_env import helper\nread=helper.read\nparse=helper.parse\ncommand=helper.command\nsource_namespace=helper.source_namespace\n')
    s=root/'support.py';s.write_text('from _inert_verifier_test_env import service_state,runtime_identity\n')
    def ref(path):return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    binding={'helper':ref(h),'support':ref(s),'installation':ref(installation),'unit':ref(unit)}
    return SimpleNamespace(binding=binding,state=state,process=process,pid=pid,root=root,unit=unit,python=python,
        directory=directory,journal=journal,admission=admission,helper=helper,release=release,inventory=inventory,argv=argv,host=host)


def test_actual_emitted_verifier_probe_binds_exact_process_unit_source_and_idle(verifier_case,monkeypatch):
    c=verifier_case
    result=execute(c.host.VERIFIER_PROBE,c.binding,monkeypatch)
    assert result['identity']['pid']==c.pid and result['identity']['start_ticks']==90000
    assert result['argv_sha256']==hashlib.sha256(c.process['argv']).hexdigest()
    assert result['release_sha256']==c.release and result['source_sha256']==c.inventory
    assert result['witness']['status']=='GENUINE_NEW_VERIFIER_IDLE_CLAIM'


@pytest.mark.parametrize('phase',['session-only','claim-intent','p0002-active'])
def test_fresh_older_idle_cannot_hide_a_newer_pending_session(verifier_case,monkeypatch,phase):
    c=verifier_case;new=c.journal.root/('session-'+'b'*24);new.mkdir()
    (new/'session.json').write_bytes((c.directory/'session.json').read_bytes())
    if phase=='claim-intent':
        (new/'p0001-claim.intent.json').write_bytes((c.directory/'p0001-claim.intent.json').read_bytes())
    elif phase=='p0002-active':(new/'p0002-import.intent.json').write_text('{"outcome":"unresolved"}')
    assert {d.name for d in c.journal.pending()}=={new.name}
    with pytest.raises(RuntimeError,match='OTHER_PENDING_SESSION'):
        execute(c.host.VERIFIER_PROBE,c.binding,monkeypatch)


def test_genuine_selected_first_idle_transient_remains_admissible(verifier_case,monkeypatch):
    c=verifier_case;(c.directory/'complete.json').unlink()  # Fixture-only transient, never a real journal mutation.
    before={p.name:p.read_bytes() for p in c.directory.iterdir()}
    assert {d.name for d in c.journal.pending()}=={c.directory.name}
    result=execute(c.host.VERIFIER_PROBE,c.binding,monkeypatch)
    assert result['witness']['session']==c.directory.name
    assert {p.name:p.read_bytes() for p in c.directory.iterdir()}==before


@pytest.mark.parametrize('change',['pending-added','selected-work-added'])
def test_pending_state_is_rechecked_after_selected_idle_validation(verifier_case,monkeypatch,change):
    c=verifier_case
    if change=='selected-work-added':(c.directory/'complete.json').unlink()  # Fixture-only unsealed first idle.
    original=c.journal.pending;calls=[]
    def pending():
        calls.append(None)
        if len(calls)==2:
            if change=='pending-added':
                new=c.journal.root/('session-'+'b'*24);new.mkdir()
                (new/'session.json').write_bytes((c.directory/'session.json').read_bytes())
            else:(c.directory/'p0002-import.intent.json').write_text('{"outcome":"unresolved"}')
        return original()
    monkeypatch.setattr(c.journal,'pending',pending)
    code='PENDING_SET_CHANGED' if change=='pending-added' else 'SELECTED_IDLE_SESSION_CHANGED'
    with pytest.raises(RuntimeError,match=code):execute(c.host.VERIFIER_PROBE,c.binding,monkeypatch)
    assert len(calls)==2


@pytest.mark.parametrize('fault',['pid','birth','argv','unit','unit-bytes','stale-proof','nonidle','proof-hash'])
def test_actual_emitted_peer_verifier_probe_rejects_changed_measurements(verifier_case,monkeypatch,fault):
    c=verifier_case
    if fault=='pid':c.state['MainPID']='999'
    elif fault=='birth':c.process['ticks']=99900
    elif fault=='argv':c.process['argv']=c.process['argv'].replace(b'hosted_service.py',b'other_service.py')
    elif fault=='unit':c.state['FragmentPath']='unbound.service'
    elif fault=='unit-bytes':c.unit.write_bytes(b'changed unit')
    elif fault=='stale-proof':
        import os,time
        os.utime(c.directory/'p0001-claim.complete.json',(time.time()-200,time.time()-200))
    elif fault=='nonidle':(c.directory/'p0002-import.intent.json').write_text('{}')
    else:
        path=c.directory/'p0001-claim.complete.json';value=json.loads(path.read_bytes())
        value['intent_sha256']='0'*64;path.write_text(json.dumps(value))
    with pytest.raises((RuntimeError,M.TransitionError,FileNotFoundError)):
        execute(c.host.VERIFIER_PROBE,c.binding,monkeypatch)


def test_actual_post_verifier_start_statements_and_idle_probe_keep_inert_data(verifier_case,inert_case,monkeypatch):
    """Execute the real post-start apply statements + NEW_PROBE; host OS is modelled."""
    import ast,inspect,textwrap
    from types import SimpleNamespace
    from qa.operator.tests.test_paused_stage_startup import host_model
    c=verifier_case;job=inert_case;host=c.host
    runtime,pins,items=host_model(job,monkeypatch)
    monkeypatch.setattr(host,'ancestor_pids',lambda:set())  # Actual verifier is a peer in this model.
    original_command=host.command
    monkeypatch.setattr(host,'command',lambda args:b'MainPID=456\n' if '--property=MainPID' in args else original_command(args))
    original_read=host.read_ref
    install=json.loads(Path(c.binding['installation']['path']).read_bytes())
    provider_ref={'path':'/modelled/provider.json','sha256':'3'*64};install['provider']=provider_ref
    monkeypatch.setattr(host,'read_ref',lambda ref:json.dumps(install).encode() if ref==c.binding['installation'] else
        json.dumps({'python':{'path':str(c.python)}}).encode() if ref==provider_ref else original_read(ref))
    def run(args,**kw):
        assert args[-1]==host.VERIFIER_PROBE and args[1:3]==['-I','-B']
        result=execute(args[-1],json.loads(kw['input']),monkeypatch)
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(result).encode())
    monkeypatch.setattr(host.subprocess,'run',run)
    seen=[]
    def processes(roots,*,verifier):
        assert verifier['identity']['pid']==c.pid and verifier['witness']['status']=='GENUINE_NEW_VERIFIER_IDLE_CLAIM'
        seen.append(verifier);return []
    monkeypatch.setattr(host,'process_inventory',processes)
    identities={job.job_id:inert.runtime_identity(job.request,job.request['prior_receipts']['import'],{'opaque':'preserved'})}
    data_calls=[]
    def data(**kw):
        data_calls.append(kw)
        result,_=host.collect(runtime,job.baseline['receiver'],identities,job.baseline['jobs'],pins,
                              storage=job.storage,verifier=c.binding)
        assert result['blockers']==[];return {'unchanged':True}
    c.admission.check=lambda:(data() and {'status':'CHECKED_NOT_STARTED'})
    witness=[]
    def child(label,mode):
        assert label=='new-first-idle' and mode=='idle'
        result=execute(M.NEW_PROBE,{'mode':'idle','helper':c.binding['helper'],'installation':c.binding['installation']},monkeypatch)
        witness.append(result);return result
    controller=SimpleNamespace(effect=lambda *a:None,operator_identity=lambda:S.runtime_identity(c.pid,str(c.python),c.argv),
                               child=child,record=lambda *a:None,data=data)
    tree=ast.parse(textwrap.dedent(inspect.getsource(M.Transition.apply)))
    nested=next(n for n in ast.walk(tree) if isinstance(n,ast.With) and any(isinstance(x,ast.Expr) and
        isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Attribute) and x.value.func.attr=='effect' and
        x.value.args and isinstance(x.value.args[0],ast.Constant) and x.value.args[0].value=='verifier-start' for x in n.body))
    start=next(i for i,n in enumerate(nested.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and
               isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='effect' and n.value.args[0].value=='verifier-start')
    end=next(i for i in range(start,len(nested.body)) if isinstance(nested.body[i],ast.Expr) and
             isinstance(nested.body[i].value,ast.Call) and any(isinstance(arg,ast.Constant) and
             arg.value=='OUTCOMES_CHANGED_BEFORE_PUBLIC_RELEASE' for arg in nested.body[i].value.args))
    fragment=ast.Module(body=nested.body[start:end+1],type_ignores=[])
    exec(compile(ast.fix_missing_locations(fragment),'<actual-post-verifier-start>','exec'),
         {'self':controller,'UNIT':M.UNIT,'need':M.need,'before':{'unchanged':True}})
    assert witness[0]['status']=='GENUINE_NEW_VERIFIER_IDLE_CLAIM' and len(seen)>=2
    assert {'new':True} in data_calls


def test_actual_process_inventory_only_exempts_exact_peer_identity(verifier_case,monkeypatch):
    from types import SimpleNamespace
    c=verifier_case;host=c.host
    proof=execute(host.VERIFIER_PROBE,c.binding,monkeypatch)
    class Proc:
        def __init__(self,value='/proc'):self.value=value
        @property
        def name(self):return self.value.rsplit('/',1)[-1]
        def __truediv__(self,other):return Proc(self.value+'/'+str(other))
        def iterdir(self):return [Proc('/proc/'+str(c.pid))]
        def read_text(self):
            if self.name=='status':return 'Uid:\t1000 1000 1000 1000\n'
            if self.name=='comm':return 'python\n'
            if self.name=='stat':return f'{c.pid} (python) '+ ' '.join(['S','1']+['0']*17+[str(c.process['ticks'])])
            raise AssertionError(self.value)
        def read_bytes(self):return c.process['argv']
    monkeypatch.setattr(host,'Path',Proc)
    monkeypatch.setattr(host,'ancestor_pids',lambda:{42})
    monkeypatch.setattr(host,'os',SimpleNamespace(getuid=lambda:1000))
    assert host.process_inventory([],verifier=proof)==[]
    wrong=deepcopy(proof);wrong['identity']['pid']=999
    assert host.process_inventory([],verifier=wrong)[0]['pid']==c.pid
    c.process['ticks']+=1
    with pytest.raises(RuntimeError,match='VERIFIER_PROCESS_CHANGED'):host.process_inventory([],verifier=proof)
    c.process['ticks']-=1;c.process['argv']+=b'--different\0'
    with pytest.raises(RuntimeError,match='VERIFIER_PROCESS_CHANGED'):host.process_inventory([],verifier=proof)
