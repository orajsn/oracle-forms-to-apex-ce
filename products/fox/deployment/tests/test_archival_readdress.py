"""Archival packaging only: no live producer, deployment or acceptance authority."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'fox'),str(ROOT/'fox/tests')]
spec=importlib.util.spec_from_file_location('archival_readdress_test',ROOT/'deployment/readdress_project_history.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
from qa.operator import retirement_handoff as h,hosted_service as service
from qa.operator.tests.test_retirement_handoff import case,finalize,I_ROOT


@pytest.mark.parametrize('raw',[b'{}',b'bad',b'{"secret":"SYNTHETIC_PRIVATE_SENTINEL"}'])
def test_parent_independent_hash_is_required_before_artifact_packaging(raw):
    with pytest.raises(Exception) as error:
        M.plan_archive(installation_raw=raw,installation_sha256='0'*64,attestation_raw=b'{}',
            members={},manifest_raw=b'{}',configuration_raw=b'{}')
    assert 'SYNTHETIC_PRIVATE_SENTINEL' not in str(error.value)


@pytest.fixture
def package(case):
    """Existing full synthetic legacy transcript fixture, not a live capture."""
    from qa.operator.tests.test_hosted_release_binding import offline_configuration,operator_configuration
    from qa.operator import product_verifier as product,retirement_remote as remote
    parent=finalize(case);old=case['destination']
    ref=lambda name,digest:{'path':'/private/config/'+name,'sha256':digest}
    installation={'schema_version':1,'scope':service.SCOPE,
        'provider':ref('C.json',old['provider_configuration_sha256']),
        'release':ref('R.json',old['release_sha256']),'admission':ref('D.json',old['configuration_sha256']),
        'retirement':{'path':'/private/state/handoffs/parent','attestation_sha256':h.sha(parent)},
        'layout':{'release_root':'/private/source/bundle','inventory':ref('inventory.json','8'*64)},
        'bounds':{'max_jobs':1,'max_polls':1,'max_seconds':60,'poll_seconds':1},'batch_pause_seconds':1}
    configuration=offline_configuration();configuration['images']={'fox':'sha256:'+'7'*64,'converter':'sha256:'+'8'*64}
    raw=h.canonical(configuration)
    manifest=product.build_manifest(operator_configuration(configuration),hosted_configuration=raw)
    r=h.canonical(manifest)
    pins={'fox':{'id':'4'*64,'image':configuration['images']['fox']},
        'forms2apex-mcp':{'id':'5'*64,'image':configuration['images']['converter']},
        'oracle-applied-ai-label':old['infrastructure']['oracle-applied-ai-label']}
    d=h.canonical(remote.admission_configuration(h.sha(r),h.sha(raw),pins))
    i=h.canonical(installation)
    return {'installation_raw':i,'installation_sha256':h.sha(i),'attestation_raw':parent,
        'members':dict(case['members']),'manifest_raw':r,'configuration_raw':d}


@pytest.mark.skipif(not I_ROOT.exists(),reason='Full retained synthetic legacy-transcript fixture unavailable')
def test_new_destination_retains_every_original_fact_and_parent_byte(package):
    before=deepcopy(package);proposal=M.plan_archive(**package)
    bundle=M.seal_archive(**package,authorized_plan_sha256=proposal['plan_sha256'])
    raw=bundle.attestation_raw;members=dict(bundle.members)
    value=h.validate_bundle(raw,members,expected_attestation_sha256=h.sha(raw),
        expected_release_sha256=h.sha(package['manifest_raw']),
        expected_configuration_sha256=h.sha(package['configuration_raw']))
    parent=json.loads(package['attestation_raw'])
    assert value['history']==parent['history'] and value['original_typed_checks']==parent['original_typed_checks']
    assert value['plan']['archival_readdress']['current_hosted_retirement_proven'] is False
    assert value['deployment_authorized'] is value['human_acceptance_recorded'] is False
    prefix='provenance/'+h.sha(package['attestation_raw'])
    assert members[prefix+'/attestation.json']==package['attestation_raw']
    assert members[prefix+'/installation.json']==package['installation_raw']
    assert members[prefix+'/manifest.json']==package['members']['destination/manifest.json']
    assert all(members[name]==data for name,data in package['members'].items() if not name.startswith('destination/'))
    assert package==before


@pytest.mark.skipif(not I_ROOT.exists(),reason='Full retained synthetic legacy-transcript fixture unavailable')
@pytest.mark.parametrize('fault',['parent-byte','source-byte','inventory','wrong-plan','same-destination','old-I'])
def test_rehashed_or_readdressed_changes_do_not_erase_or_replay_history(package,fault):
    proposal=M.plan_archive(**package)
    if fault=='parent-byte':package['attestation_raw']+=b' '
    elif fault=='source-byte':package['members']['source/manifest.json']+=b' '
    elif fault=='inventory':package['members']['unlisted.json']=b'{}'
    elif fault=='same-destination':
        package['manifest_raw']=package['members']['destination/manifest.json']
        package['configuration_raw']=package['members']['destination/configuration.json']
    elif fault=='old-I':package['installation_raw']+=b' '
    with pytest.raises(Exception):
        M.seal_archive(**package,authorized_plan_sha256='0'*64 if fault=='wrong-plan' else proposal['plan_sha256'])


@pytest.mark.skipif(not I_ROOT.exists(),reason='Full retained synthetic legacy-transcript fixture unavailable')
@pytest.mark.parametrize('fault',['old-authorization','old-destination','future-issuance'])
def test_invalid_past_authority_is_not_fixed_by_packaging_a_new_destination(package,fault):
    parent=json.loads(package['attestation_raw'])
    if fault=='old-authorization':parent['authorized_plan_sha256']='0'*64
    elif fault=='old-destination':
        parent['plan']['destination']['release_sha256']='0'*64
        parent['authorized_plan_sha256']=h.sha(h.canonical(parent['plan']))
    else:parent['issued_at_utc']='2999-01-01T00:00:00+00:00'
    # Rehash a synthetic enclosing reference to exercise intrinsic history
    # checks, not just an independent-parent-hash rejection.
    raw=h.canonical(parent);installation=json.loads(package['installation_raw'])
    installation['retirement']['attestation_sha256']=h.sha(raw)
    package.update(attestation_raw=raw,installation_raw=h.canonical(installation))
    package['installation_sha256']=h.sha(package['installation_raw'])
    with pytest.raises(Exception):M.plan_archive(**package)
