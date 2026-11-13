"""Full fact-index cache differentials; no source authenticity or grants."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import json

import pytest

from fox import forms_blueprint as blueprint,prototype_read_scope as scope
from fox import prototype_design_context as context
from fox.opaf import canonical_hash,OpafError
from test_prototype_design_context import example,structural,TARGET


@pytest.fixture
def case(tmp_path):
    packet,plan,candidates,proposed,receipt=example()
    root=tmp_path/'prototype-pipeline';root.mkdir()
    return root,packet,plan,candidates,proposed,receipt


@pytest.fixture
def calls(monkeypatch):
    original=blueprint._source_fact_index_uncached;seen=[]
    def measured(packet):seen.append(1);return original(packet)
    monkeypatch.setattr(blueprint,'_source_fact_index_uncached',measured)
    return seen


def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def assert_refs(packet,index):
    rows=[row for entry in packet['sources'] for row in entry['facts']['objects']]
    assert list(index[0])==[row['id'] for row in rows]
    assert all(index[0][row['id']] is row for row in rows)


def test_once_per_scope_value_order_and_original_borrowed_rows(case,calls):
    root,packet,*_=case
    gold=blueprint._source_fact_index_uncached(packet);calls.clear()
    before=deepcopy(packet)
    assert blueprint._index_cache_eligible(packet)
    facts=packet['sources'][0]['facts'];assert facts['modules'][0] is facts['objects'][0]
    with scope.readonly_proof_scope(root):
        results=[blueprint.source_fact_index(packet) for _ in range(3)]
        for index in results:
            assert type(index)is tuple and len(index)==3 and encode(index)==encode(gold)
            assert_refs(packet,index)
        assert results[0][0] is not results[1][0]
        assert results[0][1] is not results[1][1] and results[0][2] is not results[1][2]
    assert len(calls)==1 and packet==before
    with scope.readonly_proof_scope(root):blueprint.source_fact_index(packet)
    assert len(calls)==2


def test_warm_equal_packet_clone_rebinds_to_current_rows_not_first_input(case,calls):
    root,packet,*_=case;other=deepcopy(packet)
    with scope.readonly_proof_scope(root):
        first=blueprint.source_fact_index(packet);second=blueprint.source_fact_index(other)
        assert encode(first)==encode(second);assert_refs(other,second)
        first_id=next(iter(first[0]));assert first[0][first_id] is not second[0][first_id]
    assert len(calls)==1


def test_evidence_allowed_and_map_mutation_cannot_poison_cache(case,calls):
    root,packet,*_=case;gold=blueprint._source_fact_index_uncached(packet);calls.clear()
    with scope.readonly_proof_scope(root):
        objects,evidence,allowed=blueprint.source_fact_index(packet)
        objects.clear();evidence.clear();allowed.clear()
        assert encode(blueprint.source_fact_index(packet))==encode(gold)
    assert len(calls)==1


def test_mutating_borrowed_row_still_mutates_packet_and_forces_cold_check(case,calls):
    root,packet,*_=case
    with scope.readonly_proof_scope(root):
        index=blueprint.source_fact_index(packet);row=packet['sources'][0]['facts']['objects'][0]
        index[0][row['id']]['name']='Changed caller input row'
        assert row['name']=='Changed caller input row'
        with pytest.raises(ValueError) as cold:blueprint._source_fact_index_uncached(packet)
        with pytest.raises(type(cold.value)):blueprint.source_fact_index(packet)
    assert len(calls)==3


@pytest.mark.parametrize('change',['structure','safety','fact-safety','selection','chunks','objects','owner',
    'code-unit','bool-int','source-order'])
def test_every_packet_change_revalidates_like_original(case,calls,change):
    root,packet,*_=case
    with scope.readonly_proof_scope(root):
        blueprint.source_fact_index(packet)
        if change=='structure':packet['unexpected']=True
        elif change=='safety':packet['safety']['code_executed']=True
        elif change=='fact-safety':packet['sources'][0]['facts']['safety']['import_allowed']=True
        elif change=='selection':packet['selection_status']='METADATA_ONLY'
        elif change=='chunks':packet['chunks'][0]['text']='Changed without a new unit hash'
        elif change=='objects':packet['sources'][0]['facts']['objects'].reverse()
        elif change=='owner':packet['sources'][0]['facts']['objects'][1]['parent_id']='unknown'
        elif change=='code-unit':packet['sources'][0]['facts']['code_units'][0]['bytes']+=1
        elif change=='bool-int':packet['schema_version']=True
        else:packet['sources'][0]['facts']['items'].reverse()
        with pytest.raises(ValueError) as cold:blueprint._source_fact_index_uncached(packet)
        with pytest.raises(type(cold.value)):blueprint.source_fact_index(packet)
    assert len(calls)==3


@pytest.mark.parametrize('change',['tuple','nonstring-key','subclass','scalar-subclass','nan','cycle'])
def test_nonplain_canonical_collisions_fall_back_to_original(case,calls,monkeypatch,change):
    root,packet,*_=case
    with scope.readonly_proof_scope(root):
        blueprint.source_fact_index(packet)
        if change=='tuple':
            old=canonical_hash(packet);packet['sources']=tuple(packet['sources']);assert canonical_hash(packet)==old
        elif change=='nonstring-key':packet[1]='x'
        elif change=='subclass':
            class Custom(dict):pass
            packet=Custom(packet)
        elif change=='scalar-subclass':
            class Custom(str):pass
            packet['scope']=Custom(packet['scope'])
        elif change=='nan':packet['schema_version']=float('nan')
        else:packet['cycle']=packet
        assert not blueprint._index_cache_eligible(packet)
        def forbidden(*a,**kw):pytest.fail('Nonplain data reached canonical cache key.')
        monkeypatch.setattr(scope,'cached_read',forbidden)
        with pytest.raises(ValueError) as cold:blueprint._source_fact_index_uncached(packet)
        with pytest.raises(type(cold.value)):blueprint.source_fact_index(packet)
    assert len(calls)==3


@pytest.mark.parametrize('budget',['_INDEX_CACHE_MAX_NODES','_INDEX_CACHE_MAX_DEPTH','_INDEX_CACHE_MAX_TEXT'])
def test_eligibility_budget_fallback_does_not_reject_valid_packet(case,calls,monkeypatch,budget):
    root,packet,*_=case;gold=blueprint._source_fact_index_uncached(packet);calls.clear()
    monkeypatch.setattr(blueprint,budget,0)
    with scope.readonly_proof_scope(root):assert blueprint.source_fact_index(packet)==gold
    assert len(calls)==1


def test_no_scope_rebuilds_and_never_uses_guard(case,calls,monkeypatch):
    _,packet,*_=case
    def forbidden(*a):pytest.fail('Outside scope must retain original behavior.')
    monkeypatch.setattr(blueprint,'_index_cache_eligible',forbidden)
    for _ in range(2):assert_refs(packet,blueprint.source_fact_index(packet))
    assert len(calls)==2


def test_new_scope_root_thread_task_and_execution_boundaries(case,calls,tmp_path):
    root,packet,*_=case;other=tmp_path/'other';other.mkdir()
    with scope.readonly_proof_scope(root):
        blueprint.source_fact_index(packet)
        copied=copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(copied.run,blueprint.source_fact_index,packet)
            with pytest.raises(OpafError):future.result()
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(other):blueprint.source_fact_index(packet)
        with pytest.raises(OpafError):scope.forbid_execution()
    with scope.readonly_proof_scope(other):blueprint.source_fact_index(packet)
    assert len(calls)==2
    async def run():
        with scope.readonly_proof_scope(root):
            blueprint.source_fact_index(packet)
            async def foreign():return blueprint.source_fact_index(packet)
            with pytest.raises(OpafError):await asyncio.create_task(foreign())
    asyncio.run(run())


def test_full_review_context_bytes_identical_and_not_authority_cached(case,calls):
    root,packet,plan,originals,proposed,_=case
    candidates,refs=structural(packet,plan,originals,proposed);current=candidates[-1]['focus_id'];refs.pop(current)
    before=deepcopy((packet,plan,candidates,refs))
    gold=context.build_review_context(packet,plan,candidates,refs,expected_target_sha256=TARGET,focus_id=current)
    calls.clear()
    with scope.readonly_proof_scope(root):
        for _ in range(2):assert encode(context.build_review_context(packet,plan,candidates,refs,
            expected_target_sha256=TARGET,focus_id=current))==encode(gold)
        altered=deepcopy(refs);altered[next(iter(altered))]['proof_sha256']='invalid'
        with pytest.raises(ValueError):context.build_review_context(packet,plan,candidates,altered,
            expected_target_sha256=TARGET,focus_id=current)
    assert len(calls)==1 and (packet,plan,candidates,refs)==before
    assert gold['authority_granted'] is False and gold['processing_consent_verified'] is False


@pytest.mark.parametrize('limit',['MAX_CACHED_VALUES','MAX_CACHED_VALUE_BYTES','MAX_CACHE_BYTES'])
def test_global_cache_capacity_fails_closed_not_eligibility_fallback(case,monkeypatch,limit):
    root,packet,*_=case;before=deepcopy(packet)
    # Unlike an eligibility walk budget (cold fallback), global cache capacity
    # is an existing fail-closed operational bound and must never be swallowed.
    monkeypatch.setattr(scope,limit,0 if limit=='MAX_CACHED_VALUES' else 1)
    with scope.readonly_proof_scope(root),pytest.raises(OpafError):blueprint.source_fact_index(packet)
    assert packet==before and scope.current_read_root() is None


def test_v2_known_triplets_fast_clone_exact_public_types_order_identity_and_logical_bytes(case,calls,monkeypatch,record_property):
    root,packet,*_=case
    objects,evidence,allowed=blueprint._source_fact_index_uncached(packet);calls.clear()
    before=deepcopy((packet,evidence,allowed))
    old=(list(objects),evidence,allowed)
    carrier=blueprint._fact_index_carrier(objects,evidence,allowed)
    assert type(carrier)is list and encode(carrier)==encode(old)
    assert scope._json_tree_copy_bytes(old)is None
    assert type(scope._json_tree_copy_bytes(carrier))is bytes
    original_copy,original_loads=scope.deepcopy,scope.json.loads
    copies={'deepcopy':0,'loads':0}
    def copied(value):copies['deepcopy']+=1;return original_copy(value)
    def loaded(*a,**kw):copies['loads']+=1;return original_loads(*a,**kw)
    monkeypatch.setattr(scope,'deepcopy',copied);monkeypatch.setattr(scope.json,'loads',loaded)
    with scope.readonly_proof_scope(root):
        results=[blueprint.source_fact_index(packet)for _ in range(4)]
        for public in results:
            assert type(public)is tuple and encode(public)==encode((objects,evidence,allowed))
            assert_refs(packet,public)
            assert list(public[1])==list(evidence) and list(public[2])==list(allowed)
            assert all(type(row)is tuple and len(row)==3 and all(type(v)is str for v in row)
                for rows in public[2].values()for row in rows)
        assert scope._state.get()['bytes']==len(encode(old))
        assert next(iter(scope._state.get()['cache'].values()))[0]is True
        owner=next(iter(allowed));results[0][2][owner].append(('mutated','not source evidence','unknown'))
        assert results[1][2][owner]==allowed[owner] and results[0][2][owner]is not results[1][2][owner]
    assert len(calls)==1 and copies=={'deepcopy':0,'loads':4}
    assert (packet,evidence,allowed)==before
    record_property('authored_fact_carrier_fast_counts',json.dumps({'objects':len(objects),
        'triples':sum(map(len,allowed.values())),'logical_serialized_bytes':len(encode(old)),
        'public_sha256':canonical_hash((objects,evidence,allowed)),'copies':copies},sort_keys=True))


def test_v1_purpose_cannot_supply_a_stale_value_to_v2_carrier(case,calls):
    root,packet,*_=case
    with scope.readonly_proof_scope(root):
        scope.cached_read(root,'active_focus',{'purpose':'fox-full-source-fact-index-v1','packet':packet},
            lambda:(['authored-stale-id'],{},{}))
        public=blueprint.source_fact_index(packet)
        assert_refs(packet,public)
        keys=scope._state.get()['cache']
        assert len(keys)==2
        assert ('active_focus',canonical_hash({'purpose':'fox-full-source-fact-index-v2','packet':packet}))in keys
    assert len(calls)==1


@pytest.mark.parametrize('change',['allowed-subclass','owner-list-subclass','triple-subclass','triple-list',
    'short-triple','nonstring-part','owner-subclass','evidence-subclass','evidence-value-subclass',
    'shared-owner-list','crossalias','same-empty-dict','partial'])
def test_codec_unsupported_shapes_and_mutable_aliases_preserve_tuple_passthrough(case,monkeypatch,change):
    class CustomDict(dict):pass
    class CustomList(list):pass
    class CustomTuple(tuple):pass
    class CustomStr(str):pass
    root,packet,*_=case
    objects,_,_=blueprint._source_fact_index_uncached(packet)
    names=list(objects);first,second=names[:2]
    evidence={first:first};allowed={first:[('kind','"value"',first)]}
    if change=='allowed-subclass':allowed=CustomDict(allowed)
    elif change=='owner-list-subclass':allowed[first]=CustomList(allowed[first])
    elif change=='triple-subclass':allowed[first][0]=CustomTuple(allowed[first][0])
    elif change=='triple-list':allowed[first][0]=list(allowed[first][0])
    elif change=='short-triple':allowed[first][0]=('kind','value')
    elif change=='nonstring-part':allowed[first][0]=('kind',False,first)
    elif change=='owner-subclass':allowed={CustomStr(first):allowed[first]}
    elif change=='evidence-subclass':evidence=CustomDict(evidence)
    elif change=='evidence-value-subclass':evidence[first]=CustomStr(first)
    elif change=='shared-owner-list':allowed[second]=allowed[first]
    elif change=='crossalias':evidence[first]=allowed[first]
    elif change=='same-empty-dict':evidence=allowed={}
    else:allowed[second]=[['unsupported','shape',second]]
    before=deepcopy((evidence,allowed))
    carrier=blueprint._fact_index_carrier(objects,evidence,allowed)
    assert type(carrier)is tuple and carrier[1]is evidence and carrier[2]is allowed
    assert encode(carrier)==encode((list(objects),evidence,allowed))
    assert (evidence,allowed)==before
    monkeypatch.setattr(blueprint,'_source_fact_index_uncached',lambda packet:(objects,evidence,allowed))
    with scope.readonly_proof_scope(root):
        public=blueprint.source_fact_index(packet);again=blueprint.source_fact_index(packet)
        assert_refs(packet,public)
        assert type(public[1])is type(evidence) and type(public[2])is type(allowed)
        assert encode(public)==encode((objects,evidence,allowed))
        assert next(iter(scope._state.get()['cache'].values()))[0]is False
        if change=='shared-owner-list':assert public[2][first]is public[2][second]
        elif change=='crossalias':assert public[1][first]is public[2][first]
        elif change=='same-empty-dict':assert public[1]is public[2]
        elif allowed:
            owner=next(iter(allowed))
            assert type(public[2][owner])is type(allowed[owner])
            assert type(public[2][owner][0])is type(allowed[owner][0])
            assert all(type(a)is type(b)for a,b in zip(public[2][owner][0],allowed[owner][0]))
        assert public[2]is not again[2]


def test_public_source_fact_whitelist_decisions_unchanged_by_known_codec(case):
    root,packet,*_=case
    gold=blueprint._source_fact_index_uncached(packet)
    owner=next(iter(gold[2]));kind,value,ref=gold[2][owner][0]
    claim={'source_object_id':owner,'kind':kind,'value':json.loads(value),'reason':'Authored exact source fact',
        'status':'source_fact','evidence_refs':[ref]}
    assert blueprint.validate_claim_evidence(claim,*gold)is None
    with scope.readonly_proof_scope(root):
        index=blueprint.source_fact_index(packet)
        assert blueprint.validate_claim_evidence(claim,*index)is None
        altered={**claim,'value':'not the retained source fact'}
        with pytest.raises(ValueError):blueprint.validate_claim_evidence(altered,*index)
        assert_refs(packet,index)
