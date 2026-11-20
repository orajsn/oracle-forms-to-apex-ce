"""Saved same-catalog API evidence, using isolated SQLite and a compiler double.

No model, SQLcl, Oracle connection, or human acceptance is exercised.
"""
import json

import pytest

from fox import xml_mapping_job as jobs
from test_xml_mapping_web import (
    client, connection, finish, installed_compiler, no_external_actions, settings,
)


def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Saved mapping reads must not generate, seal, validate or compile.')

    for name in ('generate_xml_package', '_seal_validated_xml_package',
                 'validate_xml_package', 'validate_offline'):
        monkeypatch.setattr(jobs.xml_mapping, name, forbidden)


def files(job):
    return {p.relative_to(job).as_posix(): p.read_bytes()
            for p in job.rglob('*') if p.is_file()}


def rows(root):
    with connection(root)() as db:
        return {table: [tuple(row) for row in db.execute(f'SELECT * FROM {table} ORDER BY rowid')]
                for table in ('runs', 'events', 'acceptances')}


def test_same_catalog_history_detail_download_and_uuid_return_exact_saved_result(client, monkeypatch):
    c, root, pid, body, run = finish(client)
    job = root / 'jobs' / run['id']
    # Confirm the regression is the current-catalog path, not an upgrade fallback.
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    assert snapshot['catalog_sha256'] == jobs.xml_mapping.mapping_catalog()['catalog_sha256']
    before_files, before_rows = files(job), rows(root)
    package = before_files['xml-mapping/apexlang.zip']
    forbid_execution(monkeypatch)

    detail = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}")
    assert detail.status_code == 200 and detail.json() == run
    history = c.get(f'/api/projects/{pid}/xml-mapping')
    assert history.status_code == 200 and history.json()['runs'] == [run]
    project = c.get(f'/api/projects/{pid}')
    assert project.status_code == 200 and project.json()['runs'] == [run]
    download = c.get(run['download_url'])
    assert download.status_code == 200 and download.content == package
    assert download.headers['X-FOX-Runtime-Verified'] == 'false'
    assert download.headers['X-FOX-Business-Acceptance'] == 'not-asserted'
    replay = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert replay.status_code == 202 and replay.json() == run
    assert run['format_validated'] is True
    assert run['runtime_verified'] is False and run['business_behavior_accepted'] is False
    assert files(job) == before_files
    assert rows(root) == before_rows


@pytest.mark.parametrize('target', ['candidate', 'package', 'log', 'snapshot', 'result'])
@pytest.mark.parametrize('change', ['alter', 'remove'])
def test_same_catalog_corrupt_or_missing_saved_evidence_fails_without_repair(
        client, monkeypatch, target, change):
    c, root, pid, body, run = finish(client)
    job = root / 'jobs' / run['id']
    directory = job / 'xml-mapping'
    paths = {'candidate': directory / 'candidate.zip', 'package': directory / 'apexlang.zip',
             'log': next((directory / 'validation').glob('offline-*.log')),
             'snapshot': job / 'source-snapshot.json', 'result': directory / 'result.json'}
    path = paths[target]
    if change == 'alter':
        path.write_bytes(path.read_bytes() + b' TAMPER')
    else:
        path.unlink()
    before_files, before_rows = files(job), rows(root)
    forbid_execution(monkeypatch)

    assert c.get(run['download_url']).status_code == 409
    detail = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}")
    assert detail.status_code == 200
    damaged = detail.json()
    assert damaged['state'] == 'ATTENTION' and damaged['format_validated'] is False
    assert damaged['download_url'] is None and damaged['package_sha256'] is None
    assert damaged['runtime_verified'] is False and damaged['business_behavior_accepted'] is False
    history = c.get(f'/api/projects/{pid}/xml-mapping')
    assert history.status_code == 200 and history.json()['available'] is False
    assert history.json()['runs'] == [damaged]
    replay = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    if target == 'snapshot':
        assert replay.status_code == 409
        assert replay.headers['X-FOX-Admission'] == 'uncertain'
    else:
        assert replay.status_code == 202 and replay.json() == damaged
    assert files(job) == before_files
    assert rows(root) == before_rows
