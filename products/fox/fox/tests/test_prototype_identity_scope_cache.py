"""Operation-local pure metadata caching; never processing or live evidence."""
import asyncio
import json
from contextvars import copy_context
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor

import pytest

from fox import prototype_dsc_identity_repair as dsc,prototype_read_scope as scope
from fox.opaf import OpafError,canonical_hash
from test_prototype_dsc_identity_repair import metadata_root


@pytest.fixture
def case(tmp_path):
    root,child,request,candidate,packet,write=metadata_root(tmp_path,dsc.TASK_POLICY)
    payload={'request':request,'candidate':candidate,'candidate_sha256':canonical_hash(candidate)}
    expected={'mapper':dsc.model_task(child,'mapper',request,write=True),
        'reviewer':dsc.model_task(child,'reviewer',payload,write=True)}
    return root,child,request,payload,expected,write


@pytest.fixture
def builds(monkeypatch):
    original=dsc.identity.build_identity_supplement;calls=[]
    def measured(documents):
        calls.append([name for name,_ in documents]);return original(documents)
    monkeypatch.setattr(dsc.identity,'build_identity_supplement',measured)
    return calls


def test_same_scope_roles_have_identical_bytes_and_one_build(case,builds):
    root,child,request,payload,expected,_=case
    before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with scope.readonly_proof_scope(root):
        for _ in range(3):
            for role,body in (('mapper',request),('reviewer',payload)):
                task=dsc.model_task(child,role,body,write=False)
                assert task==expected[role]
                assert json.dumps(task,sort_keys=True,ensure_ascii=False,allow_nan=False).encode()==(child/(role+'-metadata-task.json')).read_bytes()
    assert len(builds)==1
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}==before


def test_outside_scope_and_new_scope_rebuild(case,builds):
    root,child,request,_,expected,_=case
    for _ in range(2):assert dsc.model_task(child,'mapper',request,write=False)==expected['mapper']
    assert len(builds)==2
    for _ in range(2):
        with scope.readonly_proof_scope(root):
            for _ in range(2):dsc.model_task(child,'mapper',request,write=False)
    assert len(builds)==4


def test_cached_value_and_relevance_are_not_shared_mutable_tasks(case,builds):
    root,child,request,payload,expected,_=case
    with scope.readonly_proof_scope(root):
        supplement=dsc._source_identity_supplement(root)
        supplement['identities'].clear()
        task=dsc.model_task(child,'mapper',request,write=False)
        task['source_identity_metadata']['identities'].clear()
        assert dsc.model_task(child,'mapper',request,write=False)==expected['mapper']
        assert dsc.model_task(child,'reviewer',payload,write=False)==expected['reviewer']
    assert len(builds)==1


@pytest.mark.parametrize('which',['manifest','source'])
def test_missing_entry_fenced_source_refuses_before_build(case,builds,which):
    root,*_=case
    path=root/('sources-manifest.json' if which=='manifest' else 'sources/source-000.xml')
    path.unlink()
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):dsc._source_identity_supplement(root)
    assert builds==[]


def test_foreign_root_and_thread_or_task_context_cannot_reuse(case,builds,tmp_path):
    root,*_=case
    with scope.readonly_proof_scope(root):
        dsc._source_identity_supplement(root)
        with pytest.raises(OpafError):dsc._source_identity_supplement(tmp_path/'foreign')
        context=copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(context.run,dsc._source_identity_supplement,root)
            with pytest.raises(OpafError):future.result()
    async def owner():
        with scope.readonly_proof_scope(root):
            dsc._source_identity_supplement(root)
            async def foreign():return dsc._source_identity_supplement(root)
            with pytest.raises(OpafError):await asyncio.create_task(foreign())
    asyncio.run(owner())
    assert len(builds)==2


def test_within_scope_source_change_cannot_escape_exit_fence(case,builds):
    root,*_=case;source=root/'sources/source-000.xml'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            original=dsc._source_identity_supplement(root)
            source.write_bytes(source.read_bytes().replace(b'COL_A',b'OTHER'))
            # The cached data is not a grant. The enclosing exit fence MUST fail.
            assert dsc._source_identity_supplement(root)==original
    assert scope.current_read_root() is None and len(builds)==1


def test_new_uncovered_source_refuses_before_cache_fill(case,builds):
    root,_,_,_,_,write=case
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            manifest=dsc.epochs.read(root/'sources-manifest.json')
            manifest['files'].append(deepcopy(manifest['files'][0]))
            write(root/'sources-manifest.json',manifest)
            dsc._source_identity_supplement(root)
    assert builds==[]


@pytest.mark.parametrize('which',['source','manifest'])
def test_changed_source_next_scope_rebuilds_and_binding_refuses(case,builds,which):
    root,child,request,_,_,write=case
    with scope.readonly_proof_scope(root):dsc.model_task(child,'mapper',request,write=False)
    if which=='source':
        path=root/'sources/source-000.xml';path.write_bytes(path.read_bytes().replace(b'COL_A',b'OTHER'))
    else:
        manifest=dsc.epochs.read(root/'sources-manifest.json');manifest['files'][0]['name']='different.xml'
        write(root/'sources-manifest.json',manifest)
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):dsc.model_task(child,'mapper',request,write=False)
    assert len(builds)==2


def test_request_binding_and_sidecar_still_checked_on_cache_hit(case,builds):
    root,child,request,_,expected,_=case
    with scope.readonly_proof_scope(root):
        assert dsc.model_task(child,'mapper',request,write=False)==expected['mapper']
        with pytest.raises(OpafError):dsc.model_task(child,'mapper',{**request,'source_binding':'0'*64},write=False)
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            dsc._source_identity_supplement(root)
            path=child/'mapper-metadata-task.json';path.write_text('{}')
            dsc.model_task(child,'mapper',request,write=False)
    assert len(builds)==2


@pytest.mark.parametrize('change',['binding','policy','relevance'])
def test_per_call_binding_selection_and_relevance_cannot_be_cached(case,builds,change):
    root,child,request,_,_,write=case
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            dsc.model_task(child,'mapper',request,write=False)
            altered=deepcopy(request)
            if change=='relevance':altered.update(owned_objects=[],context_objects=[])
            else:
                binding=dsc.epochs.read(root/'binding.json')
                binding['source_binding' if change=='binding' else 'metadata_task_policy']='0'*64
                write(root/'binding.json',binding)
            dsc.model_task(child,'mapper',altered,write=False)
    assert len(builds)==1


def test_legacy_and_standalone_selection_do_not_build_or_promote(tmp_path,builds):
    root,child,request,_,_,write=metadata_root(tmp_path)
    with scope.readonly_proof_scope(root):assert dsc.model_task(child,'mapper',request,write=False) is request
    write(root/dsc.RECORD,{'before_files':{}})
    standalone=root/dsc.PREFIX/request['focus_id'];standalone.mkdir()
    with scope.readonly_proof_scope(root):assert dsc.model_task(standalone,'reviewer',request,write=False) is request
    assert builds==[]
    write(child/'mapper-metadata-task.json',{'orphan':True})
    # A standalone repair's metadata does not authorize a legacy orphan task.
    write(root/dsc.RECORD,{'before_files':{(child/'mapper.json').relative_to(root.parent).as_posix():'0'*64}})
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):dsc.model_task(child,'mapper',request,write=False)


def test_existing_cache_budget_and_execution_boundary_unchanged(case,monkeypatch):
    root,child,request,_,_,_=case
    monkeypatch.setattr(scope,'MAX_CACHE_BYTES',1)
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):dsc._source_identity_supplement(root)
    from fox import prototype_pipeline as pipeline
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):
        pipeline._role(child,'mapper',object(),{},request,{},None,None,None)


def test_independent_projection_validation_still_rebuilds(case,builds):
    root,*_=case
    with scope.readonly_proof_scope(root):
        supplement=dsc._source_identity_supplement(root)
        assert dsc.identity.validate_identity_supplement(dsc.documents(root),supplement)==supplement
    assert len(builds)==2
