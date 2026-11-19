"""Authenticated older output survives an engine upgrade; synthetic compiler only."""
from copy import deepcopy
import json
import uuid
import pytest

from fox import xml_mapping_job as jobs
from fox.worker import process_one
from test_xml_mapping_web import (client, installed_compiler, settings, no_external_actions,
                                  finish, queue, connection)


def upgrade(monkeypatch):
    original = jobs.xml_mapping.generate_xml_package
    changed = deepcopy(jobs.xml_mapping.mapping_catalog())
    changed['revision'] += 1
    changed['implementation_sources']['xml_mapping.py'] = 'f' * 64
    changed['catalog_sha256'] = jobs.sha(jobs.encoded({k:v for k,v in changed.items() if k != 'catalog_sha256'}))
    monkeypatch.setattr(jobs.xml_mapping, 'mapping_catalog', lambda: deepcopy(changed))
    return original, changed


def test_old_completed_output_survives_upgrade_without_generator_or_compiler(client, monkeypatch):
    c, root, pid, body, result = finish(client)
    rid=result['id'];directory=root/'jobs'/rid/'xml-mapping'
    before=(directory/'apexlang.zip').read_bytes()
    original, catalog=upgrade(monkeypatch)
    def forbidden(*args, **kwargs):
        raise AssertionError('A retained read must not regenerate or compile')
    monkeypatch.setattr(jobs.xml_mapping, 'generate_xml_package', forbidden)
    monkeypatch.setattr(jobs.xml_mapping, 'validate_offline', forbidden)
    response=c.get(f'/api/projects/{pid}/xml-mapping/runs/{rid}/download')
    assert response.status_code==200 and response.content==before
    current=c.get(f'/api/projects/{pid}/xml-mapping/runs/{rid}').json()
    assert current['state']=='GENERATED' and current['package_sha256']==result['package_sha256']
    assert current['generated_units']==result['generated_units']
    assert current['runtime_verified'] is False and current['business_behavior_accepted'] is False
    monkeypatch.setattr(jobs.xml_mapping, 'generate_xml_package', original)
    # Old output does not become an ATTENTION conflict that blocks a fresh scope.
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    assert scope['available'] is True and scope['catalog_sha256']==catalog['catalog_sha256']
    new={**body,'catalog_sha256':catalog['catalog_sha256'],'request_id':str(uuid.uuid4())}
    admitted=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=new)
    assert admitted.status_code==202 and admitted.json()['id']!=rid


def test_fresh_validation_cannot_relabel_an_old_candidate(client,monkeypatch,tmp_path):
    c,root,pid,body,result=finish(client)
    candidate=(root/'jobs'/result['id']/'xml-mapping/candidate.zip').read_bytes()
    upgrade(monkeypatch)
    def forbidden(*args,**kwargs):raise AssertionError('Stale candidate must fail before compilation')
    monkeypatch.setattr(jobs.xml_mapping,'validate_offline',forbidden)
    with pytest.raises(ValueError,match='differs from fresh'):
        jobs.xml_mapping.validate_xml_package(candidate,tmp_path/'validation')


@pytest.mark.parametrize('target',['candidate','package','log','snapshot','result'])
def test_old_authenticated_run_still_rejects_changed_evidence_after_upgrade(client,monkeypatch,target):
    c,root,pid,body,result=finish(client);rid=result['id'];directory=root/'jobs'/rid/'xml-mapping'
    upgrade(monkeypatch)
    paths={'candidate':directory/'candidate.zip','package':directory/'apexlang.zip',
           'log':next((directory/'validation').glob('offline-*.log')),
           'snapshot':root/'jobs'/rid/'source-snapshot.json','result':directory/'result.json'}
    path=paths[target];path.write_bytes(path.read_bytes()+b' ')
    response=c.get(f'/api/projects/{pid}/xml-mapping/runs/{rid}/download')
    assert response.status_code==409
    assert c.get(f'/api/projects/{pid}/xml-mapping/runs/{rid}').json()['state']=='ATTENTION'


def test_queued_old_catalog_stops_before_compilation(client,monkeypatch):
    c,root,pid,body,run=queue(client)
    upgrade(monkeypatch)
    def forbidden(*args,**kwargs):raise AssertionError('Old queued job must not compile')
    monkeypatch.setattr(jobs.xml_mapping,'validate_offline',forbidden)
    process_one(connection(root),root)
    with connection(root)() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?',(run['id'],)).fetchone()[0]=='ATTENTION'
    assert not (root/'jobs'/run['id']/'xml-mapping').exists()
