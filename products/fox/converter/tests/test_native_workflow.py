import hashlib
import json
from pathlib import Path
import pytest
from forms2apex.config import Settings
from forms2apex.workflow import ConverterWorkflow
from forms2apex.native import TEMPLATE_ID
from forms2apex.review_receipts import candidate_sha256,record_review


def make_job(tmp_path):
    root=tmp_path/'native-job';intake=root/'intake';intake.mkdir(parents=True)
    raw=b'<FormModule Name="SYNTHETIC"><Block Name="RECORDS"/></FormModule>'
    (intake/'source.xml').write_bytes(raw)
    w=ConverterWorkflow(Settings(tmp_path,Path('/sql'),'F2A_APEX','FORMS2APEX_POC','https://example.invalid/ords','generator','reviewer','127.0.0.1',8090,'x'*48,'mapper-flow','reviewer-flow'))
    native={'profile_id':'native-table-form-v1','data_mode':'synthetic_test_only','table_name':'FOX_NATIVE_ORDERS','columns':[
        {'name':'ID','data_type':'NUMBER','nullable':False,'label':'ID','primary_key':True,'identity':True},
        {'name':'TITLE','data_type':'VARCHAR2','length':100,'nullable':False,'label':'Title'}]}
    (intake/'manifest.json').write_text(json.dumps({'job_id':root.name,'source_manifest_sha256':'a'*64,'native_form':native,'files':[{'packaged_name':'source.xml','sha256':hashlib.sha256(raw).hexdigest()}]}))
    w.inspect(root.name)
    spec={'job_id':root.name,'template_id':TEMPLATE_ID,'data_classification':'synthetic_or_stub_only','generator':{'model':'generator'},'native_form':native,'remediation_items':[],'mapping_summary':'Explicit synthetic fixture metadata'}
    mapper={'workflow_id':'mapper-flow','room_id':'mapper-room','model':'generator','graph_sha256':'b'*64,'request_sha256':'c'*64,'response_sha256':'d'*64,'started_at_utc':'2026-10-16T00:00:00Z','completed_at_utc':'2026-10-16T00:00:01Z'}
    reviewer={**mapper,'workflow_id':'reviewer-flow','room_id':'reviewer-room','model':'reviewer','started_at_utc':'2026-10-16T00:00:02Z','completed_at_utc':'2026-10-16T00:00:03Z'}
    record_review(root,{'job_id':root.name,'source_hash':'a'*64,'candidate':spec,'mapper_invocation':mapper,'reviewer_invocation':reviewer,'review':{'verdict':'approve','candidate_sha256':candidate_sha256(spec),'notes':'Independent fixture review','blocking_findings':[]}},*w.review_identity())
    return w,root,spec


def test_native_profile_uses_native_components_and_binding(tmp_path):
    w,root,spec=make_job(tmp_path);w.generate(root.name,json.dumps(spec))
    assert 'type: interactiveReport' in (root/'apexlang/pages/p00001-home.apx').read_text()
    assert 'type: formAutoRowProcessing' in (root/'apexlang/pages/p00002-record.apx').read_text()
    binding=w.assert_artifact_binding(root.name)
    assert binding['template_id']==TEMPLATE_ID
    assert 'native_apex_profile' in json.loads((root/'normalized-forms-inventory.json').read_text())


@pytest.mark.parametrize('extra',['prototype_html','apexlang_files'])
def test_native_profile_rejects_free_code(tmp_path,extra):
    w,root,spec=make_job(tmp_path);spec[extra]='untrusted code'
    with pytest.raises(ValueError,match='metadata only'):w.generate(root.name,json.dumps(spec))


def test_native_schema_mismatch_blocks_before_import_intent(tmp_path,monkeypatch):
    w,root,spec=make_job(tmp_path);w.generate(root.name,json.dumps(spec))
    monkeypatch.setattr(w,'native_target_preflight',lambda *args:{'scope':'isolated-test-preflight'})
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang',lambda *a:{'passed':True})
    w.validate(root.name)
    def reject(*a):raise RuntimeError('Native schema does not match')
    monkeypatch.setattr('forms2apex.native_target.verify_native_schema',reject)
    monkeypatch.setattr('forms2apex.workflow.import_apexlang',lambda *a:pytest.fail('Import must not run'))
    with pytest.raises(RuntimeError,match='schema'):w.import_draft(root.name)
    assert not (root/'import-intent.json').exists()
