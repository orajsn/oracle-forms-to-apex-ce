"""Local immutable history/publication failures; providers are authored only."""
from copy import deepcopy
from pathlib import Path

import pytest

from fox import prototype_mapping_epochs as epochs, prototype_container_epoch as container
from fox import prototype_job
from fox.opaf import OpafError
from fox.prototype_result_publication import controlled_save_result, validate_publication
from test_prototype_container_epoch import (container_case, container_source_model, next_body, process,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions, api)
from test_prototype_clause_proof import write


def queued(case):
    _, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    return epochs.read(case[4] / container.RECORD)


def test_arbitrary_self_hashed_success_is_not_publishable(container_case):
    case = container_case
    record = queued(case)
    old = (case[4] / 'prototype-result.json').read_bytes()
    forged = epochs.read(case[4] / 'prototype-result.json')
    forged.update(status='APEX_GENERATED', stage='complete')
    with pytest.raises((OpafError, ValueError)):
        controlled_save_result(case[4], forged, record)
    assert (case[4] / 'prototype-result.json').read_bytes() == old
    assert not (case[4] / container.RESULT_BASE / 'publication.json').exists()


def test_rejected_new_review_publishes_precise_failure_without_replaying_old_rejection(container_case, monkeypatch):
    case = container_case
    record = queued(case)
    count = len(case[7].calls)
    case[7].changes_role = True
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'ATTENTION', errors
    new = case[7].calls[count:]
    assert len(new) == 1 and new[0][0] == 'reviewer'
    binding = validate_publication(case[4], record)
    assert binding['status'] == 'CHANGES_REQUIRED'
    assert case[8].calls == []


@pytest.mark.parametrize('mutation', ['history-deleted', 'history-changed', 'old-history-deleted', 'latest-changed', 'publication-changed', 'archive-changed'])
def test_published_pointer_or_history_tamper_blocks_authority(container_case, monkeypatch, mutation):
    case = container_case
    record = queued(case)
    case[7].changes_role = True
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'ATTENTION', errors
    binding = validate_publication(case[4], record)
    if mutation == 'history-deleted': (case[4] / binding['history_path']).unlink()
    elif mutation == 'old-history-deleted': (case[4] / record['plan']['previous_result']['history_path']).unlink()
    elif mutation == 'history-changed':
        with (case[4] / binding['history_path']).open('ab') as stream: stream.write(b' ')
    elif mutation == 'latest-changed': write(case[4], 'prototype-result.json', {'self_hashed': True})
    elif mutation == 'publication-changed': write(case[4], container.RESULT_BASE + '/publication.json', {})
    else:
        with (case[4] / container.RESULT_BASE / 'previous-result.json').open('ab') as stream: stream.write(b' ')
    with pytest.raises((OpafError, ValueError, OSError)):
        epochs.validate_epoch_chain(case[4], case[5], (case[4] / 'source-snapshot.json').read_bytes())


@pytest.mark.parametrize('crash', ['after-history', 'after-binding'])
def test_interrupted_publication_blocks_restart_before_provider_configuration(container_case, monkeypatch, crash):
    from fox import prototype_result_publication as publication
    from fox import native_pipeline
    case = container_case
    record = queued(case)
    before = (case[4] / 'prototype-result.json').read_bytes()
    case[7].changes_role = True
    with monkeypatch.context() as failure:
        if crash == 'after-history':
            actual_save = epochs.save
            def save(path, *args, **kwargs):
                if Path(path).name == 'publication.json': raise OSError('Authored publication interruption')
                return actual_save(path, *args, **kwargs)
            failure.setattr(epochs, 'save', save)
        else:
            failure.setattr(publication.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError('Authored pointer interruption')))
        row, errors = process(case)
    assert row['state'] == 'ATTENTION'
    assert (case[4] / 'prototype-result.json').read_bytes() == before
    assert len(list((case[4] / 'prototype-results').iterdir())) == 2
    calls = deepcopy(case[7].calls)
    configured = []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configured.append(True))
    with pytest.raises((OpafError, ValueError)):
        prototype_job.run_prototype_job(case[4], approval_check=lambda _: True)
    assert configured == [] and case[7].calls == calls
