"""Real local HTTP/ZIP; provider, SQLcl and browser results are AUTHORED."""
from pathlib import Path
import importlib.util
import sys
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'fox/tests'))
_path=Path(__file__).resolve().parents[2]/'fox/tests/conftest.py'
_spec=importlib.util.spec_from_file_location('dsc_fox_isolation',_path)
_spec.loader.exec_module(importlib.util.module_from_spec(_spec))

from test_prototype_dsc_identity_repair import (dsc_case,next_body,historical_dsc_source,
    correction_case,screen_case,partition_case,container_case,container_source_model,clause_case,
    epochs_case,tmp_path,client,settings,no_external_actions)
from test_prototype_context_screen_http import _http_roundtrip
from fox import prototype_dsc_identity_repair as dsc


@pytest.mark.parametrize('tail,allowed',[
    ('authorization.json',True),('supplement.json',True),('historical-publication.json',True),
    *[('focus-'+'a'*24+'/'+name,True) for name in sorted(dsc.FOCUS_FILES)],
    ('focus-'+'a'*24+'/mapper.json',False),('focus-'+'a'*24+'/reviewer-metadata-task.json',False),
    ('attempt-000002/reviewer.json',False),('../reviewer.json',False),('extra.py',False)])
def test_fixed_dsc_sender_receiver_path_parity(tail,allowed):
    from fox.prototype_transport import _epoch_authority_member
    from forms2apex.prototype_gateway import _SCREEN_FIXED_PATHS,_SCREEN_FOCUS_PATH,_DSC_FOCUS_PATH
    path=dsc.PREFIX+'/'+tail
    assert _epoch_authority_member(path,clause_epoch=True,container_epoch=True,partition_epoch=True,screen_epoch=True) is allowed
    assert bool(path in _SCREEN_FIXED_PATHS or _SCREEN_FOCUS_PATH.fullmatch(path) or _DSC_FOCUS_PATH.fullmatch(path)) is allowed
    assert not _epoch_authority_member(path,clause_epoch=True,container_epoch=True,partition_epoch=True)


def test_five_fresh_reviews_then_real_local_gateway_output_and_download(dsc_case,monkeypatch,tmp_path_factory,record_property):
    case=dsc_case;before={p.relative_to(case[4]).as_posix():p.read_bytes() for p in case[4].rglob('*') if p.is_file()}
    calls=len(case[7].calls)
    class Client:
        def post(self,url,**kwargs):return case[0].post(url.removesuffix('mapping-epochs')+'dsc-identity-repair',**kwargs)
        def get(self,url,**kwargs):return case[0].get(url,**kwargs)
    wrapped=(Client(),*case[1:])
    def body_for_shared_harness(_):
        plan,body=next_body(case)
        return {**plan,'pending_review_focus_id':plan['projections'][0]['focus_id']},body
    result=_http_roundtrip(wrapped,monkeypatch,tmp_path_factory,next_epoch_body=body_for_shared_harness)
    for key,value in result.items():record_property(key,value)
    assert result['stage_posts']==5 and result['package_bytes']>0
    fresh=case[7].calls[calls:]
    assert [name for name,_ in fresh[:5]]==['reviewer']*5
    assert all(payload['scope']==dsc.SCOPE for _,payload in fresh[:5])
    assert sum(name=='mapper' for name,_ in fresh)==1  # Only the genuinely unstarted final focus.
    assert all((case[4]/name).read_bytes()==raw for name,raw in before.items() if name!='prototype-result.json')
