"""Receipt-bound continuation after one separately approved new mapper attempt."""
from pathlib import Path

from .opaf import OpafError, canonical_hash
from .provider_receipts import LocalProviderReceiptStore
from . import prototype_provider_reexecution as reexecution

SCOPE = 'fox-provider-checkpoint-receipt-v1'


def _job(directory):
    directory = Path(directory)
    if directory.parent.name != 'prototype-pipeline':
        return None
    job = directory.parent.parent
    if not job.name.startswith('fox-'):
        return None
    return job


def validate_recorded_receipt(directory, name, request, target, saved):
    """Verify captured response equality without auth, network, creation or writes."""
    job = _job(directory)
    marker = saved.get('provider_response_receipt')
    if job is None:
        if marker is not None:
            raise OpafError('Provider receipt has no trusted job scope.')
        return
    path = reexecution.paths(job)['authority']
    if not path.exists() and not path.is_symlink():
        if marker is not None:
            raise OpafError('Provider receipt has no durable continuation authority.')
        return
    authority = reexecution._authority(job)
    pivot = authority['plan']['pivot_focus_id']
    if Path(directory).name == pivot and name == 'mapper':
        if marker is not None:
            raise OpafError('The explicitly repeated mapper uses its separate new-attempt proof.')
        return
    remaining = {(row.get('focus_id'), row.get('role')) for row in authority['plan']['remaining_operations'] if 'role' in row}
    if (Path(directory).name, name) not in remaining:
        if marker is not None:
            raise OpafError('Historical prefix cannot acquire new provider receipts.')
        return
    if marker is None:
        raise OpafError('A new continuation response lacks its retained provider receipt.')
    output, invocation, environment, evidence = reexecution.read_captured_role(job,
        role_name=name, request=request, target=target,
        expected_wire_sha256=saved['invocation']['wire_request_sha256'])
    expected = {'schema_version': 1, 'scope': SCOPE, **evidence}
    if (canonical_hash(marker) != canonical_hash(expected)
            or canonical_hash([output, invocation, environment]) != canonical_hash(
                [saved['output'], saved['invocation'], saved['model_environment']])):
        raise OpafError('Provider checkpoint differs from the exact captured response.')


class ReceiptClient:
    """Explicit runtime wrapper; generic pending intents remain blocked."""
    def __init__(self, job, client):
        self.job, self.client = Path(job), client
        paths = reexecution.paths(job)
        if not paths['adoption'].is_file() or not paths['receipts'].is_dir() or paths['receipts'].is_symlink():
            raise OpafError('Approved continuation receipt storage is unavailable.')
        self.store = LocalProviderReceiptStore(paths['receipts'], sealed_job_root=job)

    def invoke_prepared(self, role, request, identity, *, role_name, target_profile, before_invoke):
        return self.client.invoke_prepared(role, request, identity, role_name=role_name,
            target_profile=target_profile, before_invoke=before_invoke, receipt_store=self.store)

    def recorded_receipt(self, role, request, identity, *, role_name, target_profile,
                         output, invocation, environment):
        _, _, wire = self.client._prepare_request(role, request)
        captured = reexecution.read_captured_role(self.job, role_name=role_name,
            request=request, target=target_profile, expected_wire_sha256=wire)
        if canonical_hash(captured[:3]) != canonical_hash([output, invocation, environment]):
            raise OpafError('Provider response changed before checkpoint publication.')
        return {'schema_version': 1, 'scope': SCOPE, **captured[3]}


def for_job(job, client):
    path = reexecution.paths(job)['authority']
    return ReceiptClient(job, client) if path.exists() or path.is_symlink() else client


def index_evidence(job):
    """Describe an explicitly new attempt, never recovered historical output."""
    job = Path(job)
    path = reexecution.paths(job)['authority']
    if not path.exists() and not path.is_symlink():
        return None
    authority = reexecution._authority(job)
    consumed = reexecution.validate_consumed(job, authority)
    directory = job / 'prototype-pipeline' / authority['plan']['pivot_focus_id']
    from .native_pipeline import _json
    adoption = reexecution.validate_checkpoint(directory, 'mapper', _json(directory / 'mapper.json'))
    if adoption is None:
        raise OpafError('The explicitly new mapper attempt lacks its adoption proof.')
    return {'schema_version': 1, 'scope': reexecution.SCOPE,
            'pivot_focus_id': authority['plan']['pivot_focus_id'],
            'authority_sha256': canonical_hash(authority),
            'consumed_sha256': canonical_hash(consumed),
            'adoption_sha256': canonical_hash(adoption),
            'original_unknown_intent_sha256': authority['plan']['original_unknown_intent_sha256'],
            'historical_outcome': 'unknown', 'additional_attempt_limit': 1,
            'new_attempt_adopted': True}
