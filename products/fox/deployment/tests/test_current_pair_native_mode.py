"""Modelled controller acceptance only; never invokes systemctl or Podman."""
from contextlib import nullcontext
import ast
import hashlib
import json
from copy import deepcopy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('private_native_transition',HERE.parent/'current_pair_transition.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)


def plan(version=2):
    value={'schema_version':version,'scope':M.SCOPE_V2 if version==2 else M.SCOPE,
           'controller_sha256':'a'*64}
    for number,name in enumerate(M.REFS):
        value[name]={'path':'/private/'+name+'.json','sha256':format(number+1,'x')*64}
    value['old_unit']['path']=M.UNIT.as_posix()
    if version==2:value['snapshot_adapter']={'path':'/private/adapter.py','sha256':'b'*64}
    return value


@pytest.mark.parametrize('version',[1,2])
def test_unchanged_strict_plan_has_no_implicit_native_mode(version):
    value=plan(version);raw=M.cb(value)
    assert M.plan_document(raw,M.sha(raw))==value
    assert 'operating_mode' not in value


def test_explicit_native_mode_is_bound_in_exact_plan_digest():
    value=plan();strict=M.cb(value);value['operating_mode']=M.NATIVE_MODE
    value['preclaim_preservation']={'path':'/private/inert.json','sha256':'c'*64};raw=M.cb(value)
    assert M.plan_document(raw,M.sha(raw))==value
    for altered in (strict,raw.replace(b'native-prototype',b'other-prototype')):
        with pytest.raises(M.TransitionError,match='EXACT_TRANSITION_PLAN_REQUIRED'):
            M.plan_document(altered,M.sha(raw))


def test_native_cannot_omit_preservation_reference():
    value=plan();value['operating_mode']=M.NATIVE_MODE;raw=M.cb(value)
    with pytest.raises(M.TransitionError,match='NATIVE_INERT_PRESERVATION_REFERENCE_REQUIRED'):
        M.plan_document(raw,M.sha(raw))


@pytest.mark.parametrize('authority',[None,True,'authority',{}])
@pytest.mark.parametrize('scope',[None,'fox-reviewed-preclaim-terminal-baseline-v1','fox-inert-startup-baseline-v1'])
def test_native_requires_explicit_prototype_authority_and_inert_baseline(authority,scope):
    candidate={} if authority is None else {'prototype_authority':authority}
    baseline={'scope':scope}
    if type(authority)is dict and scope=='fox-inert-startup-baseline-v1':
        # Full authority/body validation remains in the existing admission/data gates.
        M.validate_native_bindings(candidate,baseline)
    else:
        with pytest.raises(M.TransitionError):M.validate_native_bindings(candidate,baseline)


@pytest.mark.parametrize('mode',[None,True,False,'',{},[],42,'strict','native-prototype-strict-stopped-v2'])
def test_malformed_or_missing_explicit_mode_is_rejected(mode):
    value=plan();value['operating_mode']=mode;raw=M.cb(value)
    with pytest.raises(M.TransitionError,match='TRANSITION_OPERATING_MODE_INVALID'):
        M.plan_document(raw,M.sha(raw))


def test_native_mode_cannot_be_smuggled_into_schema_one():
    value=plan(1);value['operating_mode']=M.NATIVE_MODE;raw=M.cb(value)
    with pytest.raises(M.TransitionError,match='TRANSITION_PLAN_INVALID'):
        M.plan_document(raw,M.sha(raw))


@pytest.fixture
def model(tmp_path_factory,monkeypatch):
    tmp_path=tmp_path_factory.mktemp('j')
    tests=HERE
    monkeypatch.syspath_prepend(str(tests.parent.parent))
    from qa.operator import product_verifier as product
    ctx=object.__new__(M.Transition);trace=[];records={}
    unit=tmp_path/'verifier.service';unit.write_bytes(b'old unit')
    newunit=tmp_path/'new.service';newunit.write_bytes(b'new unit')
    realabsolute=M.absolute
    monkeypatch.setattr(M,'absolute',lambda value:newunit if value=='/private/new.service' else realabsolute(value))
    monkeypatch.setattr(M,'UNIT',unit)
    realpath=Path
    statfile=tmp_path/'stat';statfile.write_text('1 (modelled) '+' '.join(['0']*19+['123']))
    bootfile=tmp_path/'boot';bootfile.write_text('modelled boot')
    monkeypatch.setattr(M,'Path',lambda value:statfile if value=='/proc/self/stat' else
        bootfile if value=='/proc/sys/kernel/random/boot_id' else realpath(value))
    ctx.p={'schema_version':2,'operating_mode':M.NATIVE_MODE,
        'old_unit':{'sha256':M.sha(b'old unit')},'new_unit':{'path':'/private/new.service','sha256':M.sha(b'new unit')},
        'new_installation':{'sha256':'d'*64},'snapshot':{'sha256':'e'*64}}
    ctx.R='f'*64;ctx.cfg={'state_root':str(tmp_path/'state')};ctx.root=tmp_path/'operation';ctx.root.mkdir()
    ctx.retained={'fox':'old-fox','converter':'old-converter'}
    ctx.pins={name:{'id':'new-'+name} for name in ('fox','forms2apex-mcp')}
    ctx.old_pins={name:{'id':'old-'+name} for name in ctx.pins}
    ctx.snapshot={'runtime':{'tls':{'id':'tls'}},'output_root':str(tmp_path/'backups')}
    ctx.snapshot_raw=b'snapshot';ctx.digest='9'*64
    old={name:{'State':{'StartedAt':'original'}} for name in ctx.pins}
    sig={'old':{'fox':'old-f','converter':'old-c'},'new':{'fox':'new-f','converter':'new-c'}}
    state={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0','FragmentPath':str(unit)}
    responses={'exit':b'ExecMainStatus=0\nResult=success\n','enabled':b'enabled\n'}
    def command(argv):
        trace.append(tuple(argv))
        return responses['enabled'] if 'is-enabled' in argv else responses['exit']
    def read(path,**_kwargs):
        try:return path.read_bytes()
        except PermissionError:
            # Windows msvcrt's byte-range lock denies a second read fd, unlike
            # Linux flock. Only this authored local adapter models that read.
            assert path.name=='worker.lock' and path.is_relative_to(tmp_path)
            return b'0'
    ctx.A=SimpleNamespace(read=read,command=command,
        create_file=lambda path,raw:path.write_bytes(raw),held_stage=lambda *_a,**_k:nullcontext(),sync=lambda _:None)
    ctx.old=SimpleNamespace(release='a'*64,preflight=lambda:None,reference_raw={'release':b'old release'})
    state_root=Path(ctx.cfg['state_root']);state_root.mkdir()
    monkeypatch.setattr(product.runtime_provider,'selected_hosted',lambda:None)
    monkeypatch.setattr(product.runtime_provider,'hosted',lambda:None)
    monkeypatch.setattr(product,'JOURNAL_ROOT',state_root/'product-verifier')
    monkeypatch.setattr(product.clean,'private_root',lambda:state_root)
    monkeypatch.setattr(product.clean,'private_directory',lambda path:path.mkdir(mode=0o700))
    monkeypatch.setattr(product.promotion,'private_inputs',lambda _:None)
    ctx.service=SimpleNamespace(product=product)
    with product.PrivateJournal(ctx.old.release).lock(create=True):pass
    ctx.M=SimpleNamespace(service_state=lambda *_:deepcopy(state),verify_service_unit=lambda *_:None,
        HostCutover=SimpleNamespace(await_started=lambda *_:None,await_fox_health=lambda *_:None),
        public_health=lambda **_:{'https_verified':True})
    ctx.S=SimpleNamespace(hosted_authority=lambda *_a,**_k:'authority',_inspect=lambda *_:{'State':{'Running':False,'Pid':0}},
        _host_guard=lambda _:None,execute_under_lock=lambda *_a,**_k:None,
        read_status=lambda *_a,**_k:{'status':'COMPLETE','completion_sha256':'8'*64})
    ctx.preflight=lambda:(old,sig,deepcopy(state),{'fits_current_limits':True})
    ctx.scope=lambda:None;ctx.health=lambda:trace.append('local-health')
    before={'old_journal_inventory':{},'closed_prechecks':{},'closed_qa_stages':{}}
    ctx.data=lambda **_:deepcopy(before)
    ctx.record=lambda name,value:records.update({name:deepcopy(value)})
    ctx.effect=lambda name,argv:trace.append(name)
    ctx.child=lambda label,mode:(trace.append(label) or {'mode':mode})
    ctx.operator_identity=lambda:(trace.append('strict-identity') or {'pid':123})
    ctx.check_container=lambda *args,**kwargs:{'State':{'StartedAt':'original'}}
    return ctx,trace,records,state,responses,before


def test_native_apply_runs_normal_boundaries_but_never_starts_or_observes_strict(model):
    ctx,trace,records,*_=model
    old_root=ctx.service.product.PrivateJournal(ctx.old.release).root
    old_metadata={p.name:p.read_bytes() for p in old_root.iterdir()}
    result=ctx.apply()
    assert {p.name:p.read_bytes() for p in old_root.iterdir()}==old_metadata
    assert [x for x in trace if type(x)is str and x!='local-health']==[
        'new-structure','stop-tls','stop-fox','stop-converter','retain-fox','assign-fox',
        'retain-converter','assign-converter','start-converter','start-fox','new-admission',
        'new-readiness','verifier-reload','release-tls']
    assert result['status']=='CURRENT_PAIR_NATIVE_PROTOTYPE_UPGRADE_ACTIVATED_STRICT_STOPPED'
    assert records['complete.json']==result
    assert 'operator_first_idle' not in result and 'operator-startup.json' not in records
    assert records['native-journal-metadata.json']['status']=='NATIVE_JOURNAL_METADATA_INSTALLED_NOT_STARTED'
    journal=ctx.service.product.PrivateJournal(ctx.R)
    assert {p.name for p in journal.root.iterdir()}=={'release.json','worker.lock'}
    assert M.document((journal.root/'release.json').read_bytes())=={
        'scope':'fox-product-verifier-journal-v1','release_sha256':ctx.R}
    assert result['native_journal_metadata']==ctx.native_journal_inventory()
    with journal.lock(create=False) as next_upgrade_lease:
        next_upgrade_lease.require_active(ctx.R,journal.root)
    assert result['strict_verifier_state']['new_verifier_journal_metadata_only'] is True
    for key in ('strict_verifier_started','strict_first_idle_observed','strict_accepted_output',
        'canonical_strict_upgrade_completion_claimed','model_invoked','application_generated',
        'end_to_end_conversion_proven','human_acceptance_recorded'):
        assert result[key] is False


@pytest.mark.parametrize('fault',['extra-schema','wrong-scope','wrong-release','noncanonical','lock-bytes','missing-lock'])
def test_exact_bootstrap_metadata_refuses_invalid_binding_schema_hash_or_members(model,fault):
    ctx,*_=model;result=ctx.apply();root=ctx.service.product.PrivateJournal(ctx.R).root
    if fault=='lock-bytes':(root/'worker.lock').write_bytes(b'00')
    elif fault=='missing-lock':(root/'worker.lock').rename(root/'retained-original-lock')
    else:
        binding={'scope':'fox-product-verifier-journal-v1','release_sha256':ctx.R}
        if fault=='extra-schema':binding['schema_version']=1
        elif fault=='wrong-scope':binding['scope']='not-a-journal'
        elif fault=='wrong-release':binding['release_sha256']='0'*64
        (root/'release.json').write_bytes(M.cb(binding)+(b' ' if fault=='noncanonical' else b''))
    with pytest.raises(M.TransitionError):
        ctx.native_stopped_state(new=True,metadata=result['native_journal_metadata'])


@pytest.mark.parametrize('fault',['existing','prefix-collision','race','provider-path','unheld-lease','not-native'])
def test_bootstrap_refuses_collisions_races_wrong_provider_or_unheld_authority(model,monkeypatch,fault):
    ctx,_,records,*_=model;M.UNIT.write_bytes(b'new unit')
    product=ctx.service.product;journal=product.PrivateJournal(ctx.R)
    if fault in ('existing','prefix-collision'):
        release=ctx.R if fault=='existing' else ctx.R[:16]+'1'*48
        with product.PrivateJournal(release).lock(create=True):pass
    elif fault=='race':
        create=product.clean.private_directory
        def race(path):
            if path==journal.root:path.mkdir();(path/'other-owner.json').write_bytes(b'original')
            create(path)
        monkeypatch.setattr(product.clean,'private_directory',race)
    elif fault=='provider-path':ctx.cfg['state_root']=str(journal.root.parent/'wrong-provider')
    elif fault=='not-native':ctx.p.pop('operating_mode')
    original={p.relative_to(journal.root).as_posix():p.read_bytes() for p in journal.root.rglob('*') if p.is_file()}
    old=product.PrivateJournal(ctx.old.release)
    with old.lock(create=False) as lease:
        if fault=='unheld-lease':lease._active=False
        with pytest.raises((M.TransitionError,product.ProductVerifierError,FileExistsError,RuntimeError)):
            ctx.bootstrap_native_journal(lease)
    current={p.relative_to(journal.root).as_posix():p.read_bytes() for p in journal.root.rglob('*') if p.is_file()}
    assert current==({'other-owner.json':b'original'} if fault=='race' else original)
    assert 'native-journal-metadata.json' not in records


@pytest.mark.parametrize('version',[1,2])
def test_strict_apply_keeps_original_start_idle_and_completion(model,version):
    ctx,trace,*_=model;ctx.p.pop('operating_mode');ctx.p['schema_version']=version
    result=ctx.apply()
    assert result['status']=='CURRENT_PAIR_FORWARD_UPGRADE_ACTIVATED'
    assert trace.index('verifier-reload')<trace.index('verifier-start')<trace.index('new-first-idle')<trace.index('release-tls')
    assert 'strict_verifier_started' not in result
    assert not ctx.service.product.PrivateJournal(ctx.R).root.exists()
    assert 'native-journal-metadata.json' not in model[2]


@pytest.mark.parametrize('fault',['active','failed','pid','load','fragment','substate','exit','result','enabled','hash','journal','journal-link'])
@pytest.mark.parametrize('new',[False,True])
def test_native_stopped_observation_refuses_drift(model,fault,new):
    ctx,_,_,state,responses,_=model
    if new:M.UNIT.write_bytes(b'new unit')
    mutations={'active':('ActiveState','active'),'failed':('ActiveState','failed'),'pid':('MainPID','17'),
        'load':('LoadState','not-found'),'fragment':('FragmentPath','/other.service'),'substate':('SubState','running')}
    if fault in mutations:state[mutations[fault][0]]=mutations[fault][1]
    elif fault=='exit':responses['exit']=b'ExecMainStatus=2\nResult=success\n'
    elif fault=='result':responses['exit']=b'ExecMainStatus=0\nResult=exit-code\n'
    elif fault=='enabled':responses['enabled']=b'disabled\n'
    elif fault=='hash':M.UNIT.write_bytes(b'changed')
    else:
        path=Path(ctx.cfg['state_root'])/'product-verifier'/ctx.R[:16];path.parent.mkdir(parents=True,exist_ok=True)
        if fault=='journal':path.mkdir()
        else:
            try:path.symlink_to(path.parent/'absent',target_is_directory=True)
            except OSError:pytest.skip('Windows symlink privilege unavailable')
    with pytest.raises(M.TransitionError):ctx.native_stopped_state(new=new)


@pytest.mark.parametrize('fault',['data','old-restart','new-pair','local-health','state-before','state-after',
    'public-health','hash-after','journal-after','enabled-after','exit-after','metadata-after','binding-after','lock-after','root-after'])
def test_native_apply_refuses_late_drift_without_completion(model,fault):
    ctx,trace,records,state,responses,before=model
    original_effect=ctx.effect
    def effect(name,argv):
        original_effect(name,argv)
        if name==('release-tls' if fault.endswith('-after') else 'verifier-reload'):
            if fault=='data':before['changed']=True;ctx.data=lambda **_:{'not':'baseline'}
            elif fault in ('state-before','state-after'):state['ActiveState']='active'
            elif fault=='old-restart':ctx.check_container=lambda *_a,**_k:{'State':{'StartedAt':'restarted'}}
            elif fault=='new-pair':
                def changed(*args,**kwargs):
                    if kwargs['running']:raise M.TransitionError('EXACT_CONTAINER_STATE_CHANGED')
                    return {'State':{'StartedAt':'original'}}
                ctx.check_container=changed
            elif fault=='local-health':ctx.health=lambda:(_ for _ in ()).throw(M.TransitionError('FOX_WORKER_NOT_IDLE_HEALTHY'))
            elif fault=='public-health':ctx.M.public_health=lambda **_:(_ for _ in ()).throw(M.TransitionError('PUBLIC_WORKER_NOT_HEALTHY'))
            elif fault=='hash-after':M.UNIT.write_bytes(b'changed after TLS')
            elif fault=='journal-after':(ctx.service.product.PrivateJournal(ctx.R).root/('session-'+'a'*24)).mkdir()
            elif fault=='enabled-after':responses['enabled']=b'disabled\n'
            elif fault=='exit-after':responses['exit']=b'ExecMainStatus=2\nResult=exit-code\n'
            elif fault in ('metadata-after','binding-after','lock-after','root-after'):
                root=ctx.service.product.PrivateJournal(ctx.R).root
                if fault=='metadata-after':(root/'extra.json').write_bytes(b'{}')
                elif fault=='binding-after':(root/'release.json').write_bytes(b'{}\n')
                elif fault=='lock-after':(root/'worker.lock').write_bytes(b'changed')
                else:
                    root.rename(root.with_name(root.name+'-original'))
                    root.mkdir()
                    for name in ('release.json','worker.lock'):
                        (root/name).write_bytes((root.with_name(root.name+'-original')/name).read_bytes())
    ctx.effect=effect
    with pytest.raises(M.TransitionError) as error:ctx.apply()
    assert 'INVALID_ABSOLUTE_PATH' not in str(error.value)
    assert 'complete.json' not in records
    assert 'verifier-start' not in trace and 'new-first-idle' not in trace


@pytest.mark.parametrize('refuse',[False,True])
def test_actual_native_preflight_calls_stopped_guard_without_any_service_action(monkeypatch,tmp_path,refuse):
    import sys
    tests=HERE
    monkeypatch.syspath_prepend(str(tests))
    import test_current_pair_transition as baseline
    monkeypatch.setattr(baseline,'M',M)
    original=M.Transition.preflight;observed=[]
    def native_preflight(ctx):
        ctx.p['operating_mode']=M.NATIVE_MODE
        return original(ctx)
    def stopped(ctx,*,new):
        observed.append(new)
        if refuse:raise M.TransitionError('NATIVE_VERIFIER_EXIT_NOT_CLEAN')
    monkeypatch.setattr(M.Transition,'preflight',native_preflight)
    monkeypatch.setattr(M.Transition,'native_stopped_state',stopped)
    def check():baseline.test_transition_preflight_rechecks_exact_planned_queue_before_service_actions(
        None,'none',True,tmp_path,monkeypatch)
    if refuse:
        with pytest.raises(M.TransitionError,match='NATIVE_VERIFIER_EXIT_NOT_CLEAN'):check()
    else:check()
    assert observed==[False]


def test_native_preflight_hook_is_before_any_apply_effect():
    source=(HERE.parent/'current_pair_transition.py').read_text()
    preflight=source.split('    def preflight(self):',1)[1].split('    def apply(self):',1)[0]
    assert "if self.p.get('operating_mode')==NATIVE_MODE:self.native_stopped_state(new=False)" in preflight
    assert 'self.effect(' not in preflight


def test_default_apply_and_preflight_ast_are_unchanged_except_explicit_native_branches():
    # Measured from fox-deploy-v0.1.1 controller SHA41d0db48...; no Git,
    # private workspace or mutable second source is needed to run this test.
    expected={'apply':'dde3ad12c47455866bc4a00229ffd753cabb5715a569d0b9b9c10f864f4f263f',
              'preflight':'341c99b31007fa4c32200649b2b5476024f60b4b2afae4e9278b94c0d609f9cb'}
    def canonical_ast(value):
        if isinstance(value,ast.AST):
            return {'node':type(value).__name__,'fields':{name:canonical_ast(item)
                for name,item in ast.iter_fields(value) if name!='type_params' or item}}
        if isinstance(value,list):return [canonical_ast(item) for item in value]
        if isinstance(value,bytes):return {'bytes_hex':value.hex()}
        return value
    tree=ast.parse((HERE.parent/'current_pair_transition.py').read_bytes())
    for name,digest in expected.items():
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
        class StripNative(ast.NodeTransformer):
            def visit_If(self,node):
                if ast.unparse(node.test)=="self.p.get('operating_mode') == NATIVE_MODE":return None
                return self.generic_visit(node)
        node=StripNative().visit(node)
        raw=json.dumps(canonical_ast(node),sort_keys=True,separators=(',',':')).encode()
        assert hashlib.sha256(raw).hexdigest()==digest
