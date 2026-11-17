"""Synthetic native-pair preservation, queue identity and no-replay checks."""
import json
import hashlib
from xml.etree import ElementTree as ET

import pytest

from fox import development_source as dev
from fox.hosted_forms_jobs import HostedFormsJobs
from fox.native_preparation import prepare_native_source
from test_native_preparation import factory, pair

CODE = "BEGIN -- ordinary comment\n INSERT INTO AUDIT_LOG VALUES ('APPROVED', 123.45, 'DD-MM-YYYY'); END;"


def queued(tmp_path, code=CODE, *, outputs=None):
    queue = HostedFormsJobs(tmp_path / 'queue')
    args = dict(request_id='dev-job', project_id='project', owner_id='owner', source_set_sha256='a' * 64,
                name='synthetic.fmb', raw=b'SYNTHETIC_NOT_REAL_FMB', preparation_mode=dev.MODE)
    queue.submit(**args)
    calls = []
    state = queue.process('dev-job', prepare=lambda source, output, **kw:
                          prepare_native_source(source, output, backend_factory=factory(pair(code) if outputs is None else outputs, calls), **kw))
    return queue, args, state, calls


def result(queue):
    return queue.read_result('dev-job', project_id='project', owner_id='owner', source_set_sha256='a' * 64)


def test_native_pair_binary_and_business_code_stay_exact(tmp_path):
    queue, args, state, calls = queued(tmp_path)
    assert state['status'] == dev.PREPARED, state
    assert state['preparation_mode'] == dev.MODE and not state['model_submission_allowed']
    assert [call[0] for call in calls] == ['OVERRIDDEN', 'ALL']
    prepared = queue.root / 'dev-job/prepared/dev-job'
    assert (prepared / 'original/synthetic.fmb').read_bytes() == args['raw']
    for mode, raw in pair(CODE).items():
        assert queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant=mode.lower()) == raw
    checked = result(queue)
    assert '123.45' in checked['document']['text'] and 'ordinary comment' in checked['document']['text']
    assert next(node for node in ET.fromstring(checked['document']['text']).iter() if node.tag.endswith('Trigger')).get('TriggerText') == CODE
    manifest = json.loads((prepared / 'manifest.json').read_bytes())
    assert manifest['schema_version'] == 2 and 'redacted_source' not in manifest
    assert checked['receipt']['policy_id'] == dev.POLICY_ID


def test_credential_pair_retained_with_review_instead_of_derived_adoption(tmp_path):
    code = "BEGIN password := 'SYNTHETIC_CREDENTIAL'; END;"
    queue, args, state, calls = queued(tmp_path, code)
    assert state['status'] == dev.CREDENTIAL_REVIEW, state
    assert 'SYNTHETIC_CREDENTIAL' not in json.dumps(state)
    assert queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant='overridden') == pair(code)['OVERRIDDEN']
    with pytest.raises(ValueError):
        result(queue)
    with pytest.raises(ValueError):
        queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant='effective')


@pytest.mark.parametrize('alias', ['api-key', 'client-secret', 'auth-token', 'access-token'])
@pytest.mark.parametrize('context', ['field', 'assignment'])
def test_hyphenated_credential_alias_seals_native_review_with_exact_download(tmp_path, alias, context):
    outputs = pair("BEGIN " + alias + " := 'SYNTHETIC_CREDENTIAL'; END;")
    if context == 'field':
        outputs = {mode: raw.replace(b'<FormModule ', b'<FormModule ' + alias.encode() + b'="SYNTHETIC_CREDENTIAL" ', 1)
                   for mode, raw in pair('BEGIN NULL; END;').items()}
    queue, args, state, calls = queued(tmp_path, outputs=outputs)
    assert state['status'] == dev.CREDENTIAL_REVIEW, state
    assert 'SYNTHETIC_CREDENTIAL' not in json.dumps(state)
    for mode, raw in outputs.items():
        review = state['credential_review'][mode.lower()]
        assert review['finding_count']
        assert queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant=mode.lower()) == raw
    with pytest.raises(ValueError):
        result(queue)
    with pytest.raises(ValueError):
        queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant='effective')


@pytest.mark.parametrize('changed', [{'preparation_mode': dev.LEGACY_MODE}, {'owner_id': 'other'}, {'source_set_sha256': 'b' * 64}, {'raw': b'DIFFERENT'}])
def test_request_mode_owner_source_and_bytes_cannot_change(tmp_path, changed):
    queue, args, state, calls = queued(tmp_path)
    with pytest.raises(ValueError):
        queue.submit(**{**args, **changed})
    assert queue.process('dev-job', prepare=lambda *a, **k: pytest.fail('must never replay')) == state


@pytest.mark.parametrize('variant', ['../input', '/etc/passwd', 'manifest', 'original', 'effective/../../input'])
def test_attachment_variants_are_closed(tmp_path, variant):
    queue, *_ = queued(tmp_path)
    with pytest.raises(ValueError):
        queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant=variant)


@pytest.mark.parametrize('variant', ['overridden', 'all', 'effective'])
def test_owner_and_hash_tamper_prevent_any_review_download(tmp_path, variant):
    queue, *_ = queued(tmp_path)
    with pytest.raises(ValueError):
        queue.read_source_attachment('dev-job', project_id='project', owner_id='other', variant=variant)
    prepared = queue.root / 'dev-job/prepared/dev-job'
    (prepared / 'effective/synthetic_fmb.xml').write_bytes(b'TAMPERED')
    with pytest.raises(ValueError):
        result(queue)
    with pytest.raises(ValueError):
        queue.read_source_attachment('dev-job', project_id='project', owner_id='owner', variant=variant)
    assert queue.status('dev-job', project_id='project', owner_id='owner')['status'] == 'PROCESSING_UNKNOWN'


@pytest.mark.parametrize('tamper', ['receipt_policy', 'receipt_review', 'manifest_policy', 'manifest_mode', 'manifest_status'])
def test_resealed_policy_and_review_forgery_still_rejected(tmp_path, tamper):
    queue, *_ = queued(tmp_path)
    prepared = queue.root / 'dev-job/prepared/dev-job'
    manifest = json.loads((prepared / 'manifest.json').read_bytes())
    if tamper.startswith('receipt_'):
        path = prepared / 'effective/preservation-receipt.json'
        receipt = json.loads(path.read_bytes())
        if tamper == 'receipt_policy':
            receipt['policy_id'] = 'forged-policy'
        else:
            receipt['credential_review']['limitation'] = 'no secrets guaranteed'
        raw = json.dumps(receipt).encode()
        path.write_bytes(raw)
        record = next(row for row in manifest['files'] if row['role'] == 'preservation_receipt')
        record.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
    else:
        manifest[{'manifest_policy': 'policy_id', 'manifest_mode': 'preparation_mode', 'manifest_status': 'status'}[tamper]] = 'forged'
    raw = json.dumps(manifest).encode()
    (prepared / 'manifest.json').write_bytes(raw)
    marker_path = queue.root / 'dev-job/result.json'
    marker = json.loads(marker_path.read_bytes())
    marker['prepared_manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValueError):
        result(queue)
    assert queue.status('dev-job', project_id='project', owner_id='owner')['status'] == 'PROCESSING_UNKNOWN'


def test_claim_without_outcome_is_unknown_and_never_replayed(tmp_path):
    queue = HostedFormsJobs(tmp_path / 'queue')
    queue.submit(request_id='dev-job', project_id='project', owner_id='owner', source_set_sha256='a' * 64,
                 name='synthetic.fmb', raw=b'SYNTHETIC_NOT_REAL_FMB', preparation_mode=dev.MODE)
    (queue.root / 'dev-job/claim.json').write_bytes(b'')
    assert queue.process('dev-job', prepare=lambda *a, **k: pytest.fail('no automatic replay'))['status'] == 'PROCESSING_UNKNOWN'
