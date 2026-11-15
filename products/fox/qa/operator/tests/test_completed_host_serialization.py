"""Real gateway/worker serializers with separate immutable retained raw trees."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex.project_reviews import canonical, publish, read_object
from fox import paused_stage_preservation as core, verification_recovery as recovery
from qa.operator import paused_stage_host as host
from qa.operator.tests.test_completed_stage_host import (
    completed_host_case, bridge_case, runtime_case, mixed_inert_case, inert_case, collect,
)


@pytest.fixture
def gateway_case(completed_host_case):
    c=completed_host_case;stage=Path(c.runtime['receiver_jobs'])/c.job/'prototype-converter'
    packet=read_object(c.stage/'runtime-request.json')
    # The reused transport fixture authors both copies with worker canonical
    # bytes. Construct its original receiver records with the REAL gateway
    # publisher before taking the retention floor; leave staged worker bytes.
    for name,value in (('snapshot.json',packet['artifact_binding']),('import.json',packet['imported'])):
        path=stage/name;path.unlink();publish(path,value)
        assert path.read_bytes()==canonical(value)+b'\n'
        assert (c.stage/name).read_bytes()==canonical(value)
    c.receiver[c.job]=recovery.preclaim_tree(stage.parent)
    c.receiver_stage=stage
    return c


def raw_floor(c):
    return {'receiver':core.completed_tree(c.receiver_stage.parent),'staging':host.retained_tree(c.stage.parent),
            'qa':host.retained_tree(c.attempt)}


def test_actual_gateway_lf_worker_canonical_pair_preserves_both_raw_trees(gateway_case):
    c=gateway_case;before=raw_floor(c);expected=deepcopy(c.receiver)
    for name in ('snapshot.json','import.json'):
        assert (c.receiver_stage/name).read_bytes()==(c.stage/name).read_bytes()+b'\n'
    result,_=collect(c)
    assert result['blockers']==[] and c.receiver==expected and raw_floor(c)==before
    for name in ('runtime-request.json','runtime-evidence/browser-report.json'):
        assert (c.receiver_stage/name).read_bytes()==(c.stage/name).read_bytes()


@pytest.mark.parametrize('name',['snapshot.json','import.json'])
@pytest.mark.parametrize('where',['receiver','staging'])
@pytest.mark.parametrize('change',['space','bom','extra-lf','changed-value'])
def test_only_exact_producer_encodings_are_accepted_even_if_tree_is_remeasured(gateway_case,name,where,change):
    c=gateway_case;path=(c.receiver_stage if where=='receiver' else c.stage)/name
    raw=path.read_bytes()
    if change=='space':raw=b' '+raw
    elif change=='bom':raw=b'\xef\xbb\xbf'+raw
    elif change=='extra-lf':raw+=b'\n'
    else:
        value=json.loads(raw);value['unapproved_original_value']=True;raw=canonical(value)
    path.write_bytes(raw)
    # Updating an expected tree must not turn a different serialization/value
    # into the producer's exact saved packet; no original proof is normalized.
    c.receiver[c.job]=recovery.preclaim_tree(c.receiver_stage.parent)
    c.expected[c.job]['staging']=host.retained_tree(c.stage.parent)
    before=raw_floor(c)
    with pytest.raises(RuntimeError):collect(c)
    assert raw_floor(c)==before


@pytest.mark.parametrize('name',['snapshot.json','import.json'])
def test_copying_stage_hash_does_not_match_gateway_raw_size(gateway_case,name):
    c=gateway_case;original=deepcopy(c.receiver)
    c.receiver[c.job]['files']['prototype-converter/'+name]['sha256']=hashlib.sha256((c.stage/name).read_bytes()).hexdigest()
    before=raw_floor(c)
    with pytest.raises(RuntimeError,match='RECEIVER_STAGING_CHANGED'):collect(c)
    assert raw_floor(c)==before
    assert original[c.job]['files']['prototype-converter/'+name]['bytes']==len((c.stage/name).read_bytes())+1


@pytest.mark.parametrize('name',['runtime-request.json','runtime-evidence/browser-report.json'])
def test_request_and_report_still_require_byte_identity(gateway_case,name):
    c=gateway_case;path=c.receiver_stage/name;path.write_bytes(path.read_bytes()+b'\n')
    c.receiver[c.job]=recovery.preclaim_tree(c.receiver_stage.parent)
    before=raw_floor(c)
    with pytest.raises(RuntimeError,match='RECEIVER_STAGING_CHANGED'):collect(c)
    assert raw_floor(c)==before
