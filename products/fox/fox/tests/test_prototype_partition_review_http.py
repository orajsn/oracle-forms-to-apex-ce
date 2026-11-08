"""Epoch-five local HTTP/current authority/full package; external work authored.

No live provider, Oracle, browser or production adoption is performed.
"""
import pytest
from fox import prototype_partition_review_epoch as partition
from test_prototype_container_http import _http_roundtrip
from test_prototype_partition_review_epoch import (partition_case, next_body, container_case, container_source_model,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions, api)


def test_five_exact_http_full_zip_current_download_and_postread_races(partition_case, monkeypatch, tmp_path_factory, record_property):
    measured = _http_roundtrip(partition_case, monkeypatch, tmp_path_factory,
        epoch_module=partition, next_epoch_body=next_body)
    record_property('maximum_full_current_authority_seconds', measured['maximum_authority_seconds'])
    record_property('verified_package_bytes', measured['package_bytes'])
    assert measured['maximum_authority_seconds'] < 15, measured


def test_five_transaction_abort_keeps_orphan_and_never_resubmits(partition_case):
    case = partition_case
    _, body = next_body(case)
    calls = len(case[7].calls)
    with case[9]() as db:
        db.execute("CREATE TRIGGER partition_abort BEFORE INSERT ON events WHEN NEW.object_id LIKE '%:epoch:000005:%' BEGIN SELECT RAISE(ABORT,'Authored orphan'); END")
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert (case[4] / partition.RECORD).exists()
    assert case[0].get(api(case)).status_code == 409
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert len(case[7].calls) == calls


def test_five_private_policy_does_not_schedule_legacy_corrective_review():
    from fox import prototype_container_epoch as container
    assert partition.POLICY['corrective_projection_review_calls'] == 0
    assert partition.POLICY['new_corrective_model_calls'] == 0
    assert container.POLICY['corrective_projection_review_calls'] == 1


@pytest.mark.parametrize('path,allowed', [
    ('epochs/epoch-000005/epoch-record.json', True),
    ('epochs/epoch-000005/partition-proof-descriptor.json', True),
    ('epochs/epoch-000005/partition-proof/review/reviewer.json', True),
    ('epochs/epoch-000005/partition-proof/full-audit-context.json', True),
    ('epochs/epoch-000005/focus-' + 'a' * 24 + '/full-audit-context.json', True),
    ('epochs/epoch-000005/partition-proof/prototype_partition_review.py', False),
    ('epochs/epoch-000005/partition-proof/../reviewer.json', False),
    ('epochs/epoch-000005/partition-proof/extra.json', False),
    ('epochs/epoch-000006/epoch-record.json', False),
    ('prototype-result-publications/epoch-000005/previous-result.json', False)])
def test_five_path_sender_receiver_parity(path, allowed):
    from fox.prototype_transport import _epoch_authority_member
    from forms2apex.prototype_gateway import _PARTITION_FIXED_PATHS, _PARTITION_FOCUS_PATH
    assert _epoch_authority_member(path, clause_epoch=True, container_epoch=True, partition_epoch=True) is allowed
    assert bool(path in _PARTITION_FIXED_PATHS or _PARTITION_FOCUS_PATH.fullmatch(path)) is allowed
    assert not _epoch_authority_member(path, clause_epoch=True, container_epoch=True)
