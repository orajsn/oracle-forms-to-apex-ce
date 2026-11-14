"""Real protected source loading + SQLite inert branch; no Oracle/network/live claim."""
import ast
from contextlib import contextmanager
from copy import deepcopy
import importlib
import importlib.abc
import importlib.util
from pathlib import Path
import shutil
import sqlite3
import sys
import textwrap
from types import ModuleType

import pytest

ROOT=Path(__file__).resolve().parents[3]
for folder in(ROOT,ROOT/'fox',ROOT/'fox/tests'):
    if str(folder)not in sys.path:sys.path.insert(0,str(folder))
from qa.operator import product_queue_transport as bridge,product_verifier as product
from test_paused_stage_preservation import inert_case

LEGACY=('technical_release.py','verification_recovery.py')
CURRENT=(*LEGACY,'paused_stage_preservation.py')


def manifest(legacy=False):
    hashes=lambda names:{name:bridge._file_sha(ROOT/'fox/fox'/name)for name in names}
    return {'schema_version':2,'scope':bridge.PROJECT_SCOPE,'enabled':True,
        'images':{'fox':'sha256:'+'f'*64,'converter':'sha256:'+'e'*64},
        'modules':hashes(bridge.MODULES),'code':{name:'a'*64 for name in bridge.CODE},
        'clean_operator_code_sha256':'a'*64,'qa_source_sha256':'a'*64,'promotion_transport_sha256':'a'*64,
        'native_profile_sha256':'a'*64,'target':dict(bridge.TARGET),
        'project':{**{key:'a'*64 for key in bridge.PROJECT_HASHES},'modules':hashes(bridge.PROJECT_MODULES),
            'queue_modules':hashes(LEGACY if legacy else bridge.PROJECT_QUEUE_MODULES)}}


@contextmanager
def protected_loader(value,source_root=ROOT/'fox/fox'):
    """Execute the EXACT generated digest loop and CheckedFinder class.

    Only the /app/fox mount is mapped to actual local files. No FOX modules or
    recovery/preservation behavior are mocked; arbitrary imports stay closed.
    """
    generated=bridge.container_source()
    first=generated.index(' sources={}\n');last=generated.index(' # Compile the checked bytes',first)
    checker=textwrap.dedent(generated[first:last])
    finder=next(node for node in ast.walk(ast.parse(generated))if isinstance(node,ast.ClassDef)and node.name=='CheckedFinder')
    env={'request':{'manifest':bridge.validate_release(value)},'_require':bridge._require,
        'Path':lambda path:source_root if path=='/app/fox'else Path(path),
        'hashlib':__import__('hashlib'),'importlib':importlib}
    exec(compile(checker,'<exact-generated-source-digest-loop>','exec'),env)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[finder],type_ignores=[])),
        '<exact-generated-CheckedFinder>','exec'),env)
    loader=env['CheckedFinder']()
    saved={name:module for name,module in sys.modules.items()if name=='fox'or name.startswith('fox.')}
    for name in saved:sys.modules.pop(name)
    package=ModuleType('fox');package.__path__=['/app/fox'];sys.modules['fox']=package
    sys.meta_path.insert(0,loader)
    try:yield env
    finally:
        sys.meta_path.remove(loader)
        for name in tuple(sys.modules):
            if name=='fox'or name.startswith('fox.'):sys.modules.pop(name)
        sys.modules.update(saved)


def inert_status(case):
    recovery=importlib.import_module('fox.verification_recovery')
    store=recovery.VerificationRecovery(case.database,enabled=True)
    with sqlite3.connect(case.database.as_uri()+'?mode=ro',uri=True)as db:
        db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        return store._protected_read_status(db,case.job_id,purpose='maintenance_inert_startup_preservation',
            paired_readback=case.packet,expected_pair=case.expected,now=case.now)


def test_new_project_manifest_declares_actual_pause_module_digest():
    value=bridge.project_manifest()
    assert set(value['queue_modules'])==set(CURRENT)
    assert value['queue_modules']['paused_stage_preservation.py']==bridge._file_sha(ROOT/'fox/fox/paused_stage_preservation.py')


def test_real_checked_loader_executes_inert_status_and_preserves_history(inert_case):
    value=manifest();before=inert_case.database.read_bytes()
    with protected_loader(value):
        result=inert_status(inert_case)
        module=sys.modules['fox.paused_stage_preservation']
        assert module.__file__=='/app/fox/paused_stage_preservation.py'
        assert type(module.__loader__).__name__=='CheckedFinder'
        assert result['preservation_allowed']is True
        assert result['admission']=={'blocks_admission':True,'recovery_state':'inert_unresolved_history','retry_eligible':False}
        assert result['preserved']['closure_claimed']is result['preserved']['continuation_authorized']is False
        with pytest.raises(bridge.QueueTransportError,match='FOX_UNBOUND_DEPENDENCY'):
            importlib.import_module('fox.arbitrary_unbound_module')
    assert inert_case.database.read_bytes()==before


@pytest.mark.parametrize('version',[2,3])
def test_legacy_map_is_structural_only_and_actual_loader_still_refuses_unbound_pause(inert_case,version):
    value=manifest(legacy=True)
    if version==3:
        value.update(schema_version=3,scope=bridge.HOSTED_SCOPE,
            code={name:'a'*64 for name in bridge.HOSTED_CODE},hosted_runtime_configuration_sha256='a'*64,
            opaf_profile={'path':'deployment/project-opaf-profile-v2.json','sha256':'a'*64,
                'target_profile_sha256':'a'*64,'host_path':'/synthetic/deployment/project-opaf-profile-v2.json'})
    assert bridge.validate_release(value)==value
    with protected_loader(value):
        with pytest.raises(bridge.QueueTransportError,match='FOX_UNBOUND_DEPENDENCY'):
            inert_status(inert_case)
    with pytest.raises(bridge.QueueTransportError,match='PROJECT_QUEUE_SOURCE_CLOSURE_NOT_CURRENT'):
        bridge.require_ready(value,bridge.release_sha256(value))


@pytest.mark.parametrize('fault',['missing-required','extra','wrong-digest','malformed-digest'])
def test_malformed_or_tampered_closure_refuses(fault):
    value=manifest();queue=value['project']['queue_modules']
    if fault=='missing-required':queue.pop('verification_recovery.py')
    elif fault=='extra':queue['arbitrary.py']='a'*64
    elif fault=='malformed-digest':queue['paused_stage_preservation.py']='not-a-digest'
    else:queue['paused_stage_preservation.py']='0'*64
    with pytest.raises(bridge.QueueTransportError):
        with protected_loader(value):pytest.fail('Invalid sources reached imports')


@pytest.mark.parametrize('fault',['missing','tampered'])
def test_actual_missing_or_tampered_pause_file_rejected_before_loading(tmp_path,fault):
    value=manifest();source=tmp_path/'protected';source.mkdir()
    names={*value['modules'],*value['project']['modules'],*value['project']['queue_modules']}
    for name in names:
        if name=='paused_stage_preservation.py'and fault=='missing':continue
        shutil.copyfile(ROOT/'fox/fox'/name,source/name)
    if fault=='tampered':
        with(source/'paused_stage_preservation.py').open('ab')as stream:stream.write(b'\n# authored tamper\n')
    with pytest.raises(bridge.QueueTransportError,match='FOX_INSTALLED_MODULE_'):
        with protected_loader(value,source):pytest.fail('Unsafe file reached imports')


def test_build_manifest_generates_new_closure_with_real_current_module_bytes(tmp_path,monkeypatch):
    # Separate local test layout for the legacy test-profile filename that is
    # intentionally absent from publication; original/frozen sources untouched.
    root=tmp_path/'manifest-source';(root/'fox/fox').mkdir(parents=True);(root/'deployment').mkdir()
    for name in bridge.MODULES:shutil.copyfile(ROOT/'fox/fox'/name,root/'fox/fox'/name)
    shutil.copyfile(ROOT/'deployment/project-opaf-profile-v2.json',root/'deployment/native-beta-profile.json')
    monkeypatch.setattr(product,'ROOT',root)
    config={**product.read_config(),'schema_version':2,'scope':'fox-product-verifier-operator-config-v2'}
    value=product.build_manifest(config)
    assert set(value['project']['queue_modules'])==set(CURRENT)
    assert value['project']['queue_modules']['paused_stage_preservation.py']==bridge._file_sha(ROOT/'fox/fox/paused_stage_preservation.py')


@pytest.mark.parametrize('legacy',[False,True])
def test_real_handoff_pure_validator_handles_built_current_and_retained_closures(legacy):
    from qa.operator import retirement_handoff as handoff
    from qa.operator.tests.test_hosted_release_binding import offline_configuration,operator_configuration,canonical_bytes
    configuration=offline_configuration()
    value=product.build_manifest(operator_configuration(configuration),hosted_configuration=canonical_bytes(configuration))
    assert set(value['project']['queue_modules'])==set(CURRENT)
    if legacy:value['project']['queue_modules'].pop('paused_stage_preservation.py')
    before={name:module for name,module in sys.modules.items()if name.startswith(('qa.operator','fox.'))}
    assert handoff._destination_manifest(value)==value
    assert all(sys.modules.get(name)is module for name,module in before.items())
    extra=deepcopy(value);extra['project']['queue_modules']['unbound.py']='a'*64
    with pytest.raises(handoff.RetirementError,match='RETIREMENT_DESTINATION_MANIFEST_INVALID'):
        handoff._destination_manifest(extra)
