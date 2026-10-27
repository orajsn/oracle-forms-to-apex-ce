import hashlib
import json
import subprocess
from pathlib import Path
import pytest

from forms2apex.config import Settings
from forms2apex.workflow import ConverterWorkflow
from forms2apex.starter import TEMPLATE_ID
from forms2apex.provenance import tree_digest


@pytest.fixture
def job(tmp_path,monkeypatch):
    root=tmp_path/'fox-proof';intake=root/'intake';intake.mkdir(parents=True)
    raw=b'<FormModule Name="ORDERS"/>'
    (intake/'orders.xml').write_bytes(raw)
    (intake/'manifest.json').write_text(json.dumps({'job_id':root.name,'files':[{'packaged_name':'orders.xml','sha256':hashlib.sha256(raw).hexdigest()}]}))
    settings=Settings(tmp_path,Path('/missing/sql'),'F2A_APEX','FORMS2APEX_POC','https://example.invalid/ords','generator','reviewer','127.0.0.1',8090,'x'*48)
    workflow=ConverterWorkflow(settings);workflow.inspect(root.name)
    spec={'data_classification':'synthetic_or_stub_only','generator':{'model':'generator'},'reviewer':{'model':'reviewer','verdict':'approve'},'template_id':TEMPLATE_ID,'prototype_html':'<p>Synthetic example</p>'}
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang',lambda *a:{'passed':True})
    return workflow,root,spec


def drafted(job):
    w,r,s=job;w.generate(r.name,json.dumps(s));return w,r


@pytest.mark.parametrize('target',['intake/orders.xml','intake/manifest.json','normalized-forms-inventory.json','migration-and-exception-report.json','migration-spec.json','apexlang/pages/p00001-home.apx','fox-proof-apexlang.zip'])
def test_changed_evidence_blocks_import(job,monkeypatch,target):
    w,r=drafted(job);w.validate(r.name)
    path=r/target;path.write_bytes(path.read_bytes()+b' ')
    def forbidden(*a,**k):pytest.fail('Changed artifact reached import')
    monkeypatch.setattr('forms2apex.workflow.import_apexlang',forbidden)
    with pytest.raises(RuntimeError,match='blocked'):w.import_draft(r.name)


@pytest.mark.parametrize('change',['add','remove','rename'])
def test_tree_membership_is_bound(job,change):
    w,r=drafted(job);w.validate(r.name);p=r/'apexlang/pages/p00001-home.apx'
    if change=='add':(p.parent/'extra.apx').write_text('page 2 ()')
    elif change=='remove':p.unlink()
    else:p.rename(p.with_name('renamed.apx'))
    with pytest.raises(RuntimeError,match='blocked'):w.import_draft(r.name)


def test_mutation_during_validation_never_becomes_valid(job,monkeypatch):
    w,r=drafted(job)
    def validate(*args):
        assert args[1] != r/'apexlang'
        (r/'apexlang/pages/p00001-home.apx').write_text('changed')
        return {'passed':True}
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang',validate)
    assert not w.validate(r.name)['passed']
    assert w.status(r.name)['state']=='INVALID'


@pytest.mark.parametrize('template',[None,'unknown-template'])
def test_unprotected_template_route_rejected(job,template):
    w,r,s=job;s.pop('prototype_html');s['apexlang_files']={'application.apx':'app X ()'};s['template_id']=template
    with pytest.raises(ValueError,match='template_id'):w.generate(r.name,json.dumps(s))
    assert not (r/'apexlang').exists()


def test_authentication_override_rejected(job):
    w,r,s=job;s.pop('prototype_html');s['apexlang_files']={'shared-components/authentications.apx':'changed'}
    with pytest.raises(ValueError,match='Home page'):w.generate(r.name,json.dumps(s))


def test_source_changed_after_inspection_blocks_generation(job):
    w,r,s=job;(r/'intake/orders.xml').write_text('<FormModule Name="CHANGED"/>')
    with pytest.raises(RuntimeError,match='changed'):w.generate(r.name,json.dumps(s))


def test_unchanged_snapshot_import_and_no_reinspection(job,monkeypatch):
    w,r=drafted(job);v=w.validate(r.name)
    def imported(*args):
        assert args[4] != r/'apexlang'
        assert tree_digest(args[4])==v['artifact_binding']['draft_sha256']
        return {'application_id':123,'application_alias':'F2A_FOX_PROOF','workspace':'FORMS2APEX_POC'}
    monkeypatch.setattr('forms2apex.workflow.import_apexlang',imported)
    monkeypatch.setattr('forms2apex.workflow.runtime_login_check',lambda url:{'passed':True})
    assert w.import_draft(r.name)['artifact_binding']==v['artifact_binding']
    before=(r/'normalized-forms-inventory.json').read_bytes()
    with pytest.raises(RuntimeError):w.inspect(r.name)
    assert (r/'normalized-forms-inventory.json').read_bytes()==before


def test_uncertain_import_cannot_replay_or_regenerate(job,monkeypatch):
    w,r,s=job;w.generate(r.name,json.dumps(s));w.validate(r.name)
    def timeout(*a,**k):raise subprocess.TimeoutExpired('sql',1)
    monkeypatch.setattr('forms2apex.workflow.import_apexlang',timeout)
    with pytest.raises(subprocess.TimeoutExpired):w.import_draft(r.name)
    assert w.status(r.name)['state']=='FAILED'
    with pytest.raises(RuntimeError,match='intent'):w.generate(r.name,json.dumps(s))
    with pytest.raises(RuntimeError,match='intent'):w.inspect(r.name)


def test_regeneration_clears_old_validation(job):
    w,r,s=job;w.generate(r.name,json.dumps(s));w.validate(r.name)
    previous=w.status(r.name)['artifact_binding'];s['prototype_html']='<p>New reviewed example</p>'
    w.generate(r.name,json.dumps(s));status=w.status(r.name)
    assert status['validation'] is None and status['artifact_binding']!=previous
    with pytest.raises(RuntimeError,match='blocked'):w.import_draft(r.name)
