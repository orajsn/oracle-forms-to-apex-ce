"""Normalized source to exact local ZIP; SQLcl/browser/provider replies AUTHORED.

Real gateway/package integrity and FOX current authority run unchanged. This is
not an Oracle import, live browser check, conventional reimport or acceptance.
"""
from copy import deepcopy
import hashlib,io,json,zipfile

import pytest
from fastapi.testclient import TestClient

from fox import prototype_candidate_format as format, prototype_job
from fox.prototype_download import validate_generated_package
from fox.opaf import canonical_hash,ConverterClient
from test_prototype_job import queued as base_queued
from test_prototype_authority import prepared
from test_prototype_download_connected import connected
from test_source_history_api import settings,no_external_actions,create_app,ORIGIN,PASSWORD
from test_prototype_pipeline import PROFILE
from test_prototype_mapping_epochs import tmp_path


@pytest.fixture
def queued(base_queued,monkeypatch):
    # A new explicitly format-enabled synthetic admission, before any model call.
    root,job,db,snapshot,model,converter,configurations=base_queued
    snapshot['prototype']['candidate_format_policy']=format.POLICY
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    original=model.invoke
    def invoke(role,payload):
        base=payload if role==PROFILE['mapper'] else {k:payload[k] for k in ('request','candidate','candidate_sha256')}
        output,proof=original(role,base)
        if role==PROFILE['mapper']:
            output['source_binding']=payload['source_binding']
            for row in payload['owned_objects']:
                if row['kind']=='Item':
                    output['blueprint']['claims'].append({'id':row['id']+'-alias','source_object_id':row['id'],
                        'kind':'object.item_type','status':'source_fact','value':row['item_type'],
                        'evidence_refs':[row['id']],'reason':'Exact synthetic metadata.'})
        model.calls[-1]=(model.calls[-1][0],deepcopy(payload))
        proof.update(request_sha256=canonical_hash(payload),response_sha256=canonical_hash(output))
        return output,proof
    monkeypatch.setattr(model,'invoke',invoke)
    return base_queued


def test_normalized_candidate_exact_zip_and_http_download(connected,monkeypatch,settings,no_external_actions):
    root,job,db,profile,item,request,callbacks,model=connected
    snapshot=json.loads((job/'source-snapshot.json').read_bytes())
    assert snapshot['prototype']['candidate_format_policy']==format.POLICY
    receipts=[json.loads(p.read_bytes()) for p in (job/'prototype-pipeline').glob('focus-*/projection-receipt.json')]
    assert receipts and all(r['candidate_format_normalization']['policy']==format.POLICY for r in receipts)
    before={p.relative_to(job):p.read_bytes() for p in job.rglob('*') if p.is_file()}
    operations=deepcopy((item.calls,model.calls,model.observations))
    raw=item.adapter.read_package(job.name)
    exported=item.request['prior_receipts']['export']
    assert hashlib.sha256(raw).hexdigest()==exported['package_sha256']!='e'*64
    assert validate_generated_package(raw,request=request,export_receipt=exported)==raw
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        manifest=json.loads(archive.read('manifest.json'))
        assert manifest['files']=={name:hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist() if name!='manifest.json'}
        assert 'apexlang/application.apx' in archive.namelist()
        assert any(name.startswith('sql/f') and name.endswith('.sql') for name in archive.namelist())
    # Only the local GET byte transport is authored. FOX reconstructs current
    # consent/source/roles/normalization/reviews and validates the exact ZIP.
    byte_client=ConverterClient('http://127.0.0.1:8091','SYNTHETIC-TEST-ONLY')
    def read(method,path,*,binary=False):
        assert method=='GET' and path.endswith('/package') and binary
        return item.adapter.read_package(job.name)
    monkeypatch.setattr(byte_client,'request',read)
    monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE',str(profile))
    from fox.prototype_project_routes import configured_target
    assert configured_target()['target_profile_sha256']==snapshot['prototype']['target_profile_sha256']
    monkeypatch.setattr('fox.prototype_download.configured_download_client',lambda *a,**kw:byte_client)
    with TestClient(create_app(root,enable_worker=False),base_url=ORIGIN) as client:
        client.headers['Origin']=ORIGIN
        assert client.post('/api/login',json={'username':'synthetic-owner','password':PASSWORD}).status_code==200
        response=client.get(f"/api/projects/{snapshot['project_id']}/prototype-runs/{job.name}/download")
        assert response.status_code==200,response.text
        assert response.content==raw
        assert response.headers['x-fox-output-scope']=='generated-synthetic-prototype-not-business-accepted'
    assert (item.calls,model.calls,model.observations)==operations
    assert {p.relative_to(job):p.read_bytes() for p in job.rglob('*') if p.is_file()}==before
