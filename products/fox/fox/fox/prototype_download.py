"""Read-only generated prototype export, separate from strict release download.

No model/Oracle operation, state promotion, acceptance or conventional SQL
reimport is performed here. Missing or uncertain retained proof blocks download.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from .native_pipeline import _json
from .opaf import OpafError, canonical_hash
from .prototype_pipeline import (CONVERTER_STAGES, _artifact_json,
                                 _check_converter_receipt, authorize_prototype_request)


def configured_download_client(target_sha256, *, installation_projection=None):
    # Existing protected configuration only, after current owner/source consent
    # checks. Construction does not invoke OPAF, SQLcl or a converter stage.
    from .prototype_job import _configuration
    return _configuration(target_sha256, installation_projection=installation_projection)['gateway']


def retained_export_request(job, snapshot, target):
    """Reconstruct the exact export request from retained worker-owned artifacts."""
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(Path(job) / 'prototype-pipeline'):
        return _retained_export_request(job, snapshot, target)


def _retained_export_request(job, snapshot, target):
    from .prototype_job import validate_prototype_snapshot
    job = Path(job)
    if not re.fullmatch(r'fox-[a-f0-9]{20}', job.name) or job.is_symlink():
        raise OpafError('Invalid prototype download job.')
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if (target.get('target_profile_sha256') != selected['target_profile_sha256']
            or canonical_hash(target['target_profile']) != selected['target_profile_sha256']):
        raise OpafError('Prototype target approval changed.')
    root = job / 'prototype-pipeline'
    if root.is_symlink() or not root.is_dir():
        raise OpafError('Retained prototype proof is missing or unsafe.')
    binding = _json(root / 'binding.json')
    manifest = _json(root / 'sources-manifest.json')
    index = _json(root / 'review-index.json')
    plan = _artifact_json(root / 'native-plan.json')
    rendered = _artifact_json(root / 'rendered.json')
    expected_files = [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
                      for name, raw in documents]
    if (binding.get('project_id') != snapshot['project_id']
            or binding.get('project_name') != snapshot['project_name']
            or binding.get('source_binding') != selected['source_binding']
            or binding.get('focus_plan_sha256') != selected['focus_plan_sha256']
            or binding.get('approved_policy_id') != selected['approved_policy_id']
            or binding.get('profile_sha256') != canonical_hash(target['target_profile']['opaf']['roles'])
            or manifest.get('files') != expected_files
            or manifest.get('selected_chunk_hashes') != selected['approved_chunk_hashes']):
        raise OpafError('Prototype output differs from its approved source snapshot.')
    authority = {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
                 'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
                 'review_index_sha256': canonical_hash(index)}
    base = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
            'job_id': job.name, 'project_id': snapshot['project_id'],
            'source_binding': selected['source_binding'], 'plan_sha256': plan['plan_sha256'],
            'rendering_spec': plan['rendering_spec'], 'rendered_zip_sha256': rendered['zip_sha256'],
            'source_authority': authority}
    prior = {}
    for stage in CONVERTER_STAGES:
        request = {**base, 'prior_receipts': dict(prior)}
        receipt = _check_converter_receipt(stage, request, _json(root / (stage + '.json')))
        if (receipt.get('status') != 'COMPLETE'
                or receipt.get('business_behavior_accepted') is not False
                or _json(root / (stage + '-intent.json')) != {'request_sha256': canonical_hash(request)}):
            raise OpafError('Prototype stage completion is missing or uncertain.')
        prior[stage] = receipt
    result = _json(job / 'prototype-result.json')
    from .prototype_mapping_epochs import technical_record
    from .prototype_container_epoch import NUMBER
    from .prototype_partition_review_epoch import NUMBER as PARTITION_EPOCH
    epoch = technical_record(root)
    if epoch is not None and epoch['epoch_number'] in (NUMBER, PARTITION_EPOCH):
        from .prototype_result_publication import validate_publication
        if validate_publication(job, epoch) is None:
            raise OpafError('Prototype result publication is incomplete.')
    if (result.get('scope') != 'fox-prototype-pipeline-v1' or result.get('schema_version') != 1
            or result.get('status') != 'APEX_GENERATED' or result.get('stage') != 'complete'
            or result.get('job_id') != job.name or result.get('source_binding') != selected['source_binding']
            or result.get('converter_receipts') != prior):
        raise OpafError('Prototype export has no complete retained pipeline result.')
    authorize_prototype_request(job, request)
    return request, prior['export']


def validate_generated_package(raw, *, request, export_receipt):
    """Exact package check using the original, retained import/runtime binding."""
    from forms2apex.prototype_package import (validate_prototype_package, runtime_binding,
                                              expected_runtime_pages, canonical)
    prior = request['prior_receipts']
    validated = prior['validate']
    imported, runtime = prior['import'], prior['verify_runtime']
    binding = validated['artifact_binding']
    proof = runtime['runtime_receipt']
    if (type(raw) is not bytes or not 0 < len(raw) <= 8_000_000
            or validated['validation'].get('passed') is not True
            or type(validated['validation'].get('return_code')) is not int
            or validated['validation']['return_code'] != 0
            or canonical_hash(proof) != runtime.get('runtime_receipt_sha256')
            or export_receipt.get('runtime_receipt_sha256') != canonical_hash(proof)
            or any(proof.get(key) is not True for key in ('passed', 'authenticated', 'business_pages_tested'))
            or proof.get('business_behavior_accepted') is not False
            or any(export_receipt.get(key) is not False for key in
                   ('business_behavior_accepted', 'package_reimport_passed', 'clean_schema_install_passed'))):
        raise OpafError('Prototype export lacks exact validation/import/runtime proof.')
    expected = runtime_binding(request, imported, binding)
    if any(proof.get(key) != value for key, value in expected.items()):
        raise OpafError('Prototype runtime is not bound to the retained import.')
    pages = expected_runtime_pages(request['rendering_spec'])
    if proof.get('pages') != [{'page_id': row['page_id'], 'source_block_id': row['source_block_id'],
                             'passed': True, 'authenticated': True,
                             'checks': {key: True for key in row['checks']}} for row in pages]:
        raise OpafError('Prototype runtime page coverage is incomplete.')
    checked = validate_prototype_package(raw, request=request, imported=imported,
        runtime_receipt=proof, artifact_binding=binding, export_receipt=export_receipt)
    if checked['members']['evidence/runtime-evidence/browser-report.json'] != canonical(
            {key: value for key, value in proof.items() if key != 'artifacts'}):
        raise OpafError('Prototype browser report differs from its runtime receipt.')
    return raw
