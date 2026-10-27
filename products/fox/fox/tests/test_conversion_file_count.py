"""Preflight aligns with the existing converter limit; history remains readable."""
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

import fox.app as app_module
import fox.intake as intake
from fox.native_source import assess_native_source
from test_source_history_api import (client, settings, no_external_actions,
                                    upload, history, selected, select, detail,
                                    approvals, exclude)

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
CODE = 'CONVERSION_FILE_COUNT_LIMIT'


def readable_files(count, native=False):
    if native:
        fixtures = FIXTURES
        files = [('native.xml', (fixtures / 'native-beta.xml').read_bytes()),
                 ('native.sql', (fixtures / 'native-beta.sql').read_bytes())]
    else:
        files = [('main.xml', b'<FormModule Name="SYNTHETIC_COUNT"/>')]
    return files + [(f'note-{index:03}.txt', b'\xef\xbb\xbfSynthetic supporting note.\r\n')
                    for index in range(count - len(files))]


def checked(files):
    return [intake.checked_source(name, raw) for name, raw in files]


def test_canonical_count_preflight_matches_conversion_contract():
    assert Path(intake.__file__).resolve() == Path(__file__).resolve().parents[1] / 'fox/intake.py'
    assert Path(app_module.__file__).resolve() == Path(__file__).resolve().parents[1] / 'fox/app.py'
    assert intake.MAX_CONVERSION_FILES == 50


@pytest.mark.parametrize('count', [1, 49, 50])
def test_existing_total_file_limit_allows_up_to_fifty_readables(count):
    result = intake.inventory(checked(readable_files(count)))
    assert result['max_conversion_files'] == 50
    assert result['conversion_eligible'] is True
    assert CODE not in [item['code'] for item in result['conversion_blockers']]


@pytest.mark.parametrize('count', [51, 52, 100])
def test_more_than_fifty_is_assessable_but_not_convertible(count):
    files = checked(readable_files(count))
    result = intake.inventory(files)
    assert len(result['files']) == count
    assert result['conversion_source_bytes'] < result['max_conversion_bytes']
    assert result['missing_count'] == 0
    assert result['conversion_eligible'] is False
    assert [item['code'] for item in result['conversion_blockers']] == [CODE]
    message = result['conversion_blockers'][0]['message']
    assert str(count) in message and '50 files in total' in message
    assert 'history is retained' in message and 'coherent project' in message
    # File-count metadata must not alter source identity or original byte hashes.
    canonical = '\n'.join(item['name'] + ':' + item['sha256'] for item in sorted(files, key=lambda item: item['name']))
    assert result['source_hash'] == hashlib.sha256(canonical.encode()).hexdigest()
    assert result['source_bytes'] == sum(item['bytes'] for item in files)


def test_native_scope_blockers_are_preserved_alongside_total_file_count():
    assert assess_native_source(checked(readable_files(2, native=True)))['state'] == 'READY'
    files = checked(readable_files(51, native=True))
    native = assess_native_source(files)
    assert native['state'] == 'BLOCKED'
    assert 'UNSUPPORTED_SOURCE_KIND' in [item['code'] for item in native['blockers']]
    assert intake.inventory(files)['conversion_eligible'] is False
    assert CODE in [item['code'] for item in intake.inventory(files)['conversion_blockers']]


def test_fifty_can_queue_without_provider_execution(client):
    c, root, pid = client
    result = upload(c, pid, readable_files(50))
    response = c.post(f'/api/projects/{pid}/runs', json=approvals(result['source_hash']))
    assert response.status_code == 202, response.text
    assert response.json()['state'] == 'QUEUED'
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs').fetchall() == [('QUEUED',)]
    snapshots = list((root / 'jobs').glob('*/source-snapshot.json'))
    assert len(snapshots) == 1
    assert len(json.loads(snapshots[0].read_bytes())['files']) == 50
    # The imported fixture blocks all provider HTTP/process actions; worker is off.


@pytest.mark.parametrize('native', [False, True])
def test_fifty_one_blocks_before_queue_or_provider_but_upload_history_survives(client, monkeypatch, native):
    c, root, pid = client
    if native:
        monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-table-form-v1')
    files = readable_files(51, native=native)
    upload(c, pid, files[:50])
    result = upload(c, pid, files[50:])
    sid = selected(c, pid)['id']
    assert len(result['files']) == 51 and result['conversion_eligible'] is False
    if native:
        assert result['native_assessment']['state'] == 'BLOCKED'
    response = c.post(f'/api/projects/{pid}/runs', json=approvals(result['source_hash']))
    assert response.status_code == 409
    assert '50 files in total' in response.json()['detail']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 51
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='approved_conversion'").fetchone()[0] == 0
    assert not (root / 'jobs').exists()
    assert detail(c, pid, sid)['source_set']['file_count'] == 51


def test_oversized_historical_set_remains_selectable_and_exactly_exportable(client):
    c, root, pid = client
    files = readable_files(51)
    upload(c, pid, files[:50])
    first = selected(c, pid)
    upload(c, pid, files[50:])
    oversized = selected(c, pid)
    assert select(c, pid, first['id'], oversized['id']).status_code == 200
    current = c.get(f'/api/projects/{pid}').json()['inventory']
    assert current['conversion_eligible'] is True
    saved = detail(c, pid, oversized['id'])
    assert saved['source_set']['is_selected'] is False
    assert saved['source_set']['file_count'] == 51
    assert saved['assessment_summary']['source_checks_passed'] is False
    response = c.get(f'/api/projects/{pid}/source-sets/{oversized["id"]}/download')
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {name for name, _ in files} | {'fox-source-set.json'}
        for name, raw in files:
            assert archive.read(name) == raw
        assert len(json.loads(archive.read('fox-source-set.json'))['files']) == 51
    assert select(c, pid, oversized['id'], first['id']).status_code == 200
    assert c.get(f'/api/projects/{pid}').json()['inventory']['conversion_eligible'] is False
    assert c.post(f'/api/projects/{pid}/runs', json=approvals(oversized['source_hash'])).status_code == 409
    assert len(history(c, pid)['source_sets']) == 2


def test_removing_one_unrelated_member_restores_fifty_file_readiness_without_deleting_history(client):
    c, root, pid = client
    files = readable_files(51)
    upload(c, pid, files[:50])
    first = selected(c, pid)
    upload(c, pid, files[50:])
    oversized = selected(c, pid)
    first_page = detail(c, pid, oversized['id'])
    members = first_page['files']
    if first_page['files_page']['next_cursor']:
        page = c.get(f'/api/projects/{pid}/source-sets/{oversized["id"]}',
                     params={'files_after': first_page['files_page']['next_cursor']})
        assert page.status_code == 200
        members += page.json()['files']
    unwanted = next(item['id'] for item in members if item['name'] == files[-1][0])
    response = exclude(c, pid, oversized['id'], oversized['id'], [unwanted])
    assert response.status_code == 200, response.text
    assert response.json()['assessment_summary']['source_checks_passed'] is True
    assert response.json()['selected_source_set_id'] == first['id']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 51
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    assert detail(c, pid, oversized['id'])['source_set']['file_count'] == 51
