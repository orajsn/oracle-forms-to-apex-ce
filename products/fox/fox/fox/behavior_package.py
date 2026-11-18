"""Fresh derivative packages; parent mapping/validation remain historical."""
from copy import deepcopy
import hashlib
import json

from .forms_behavior_plan import build_behavior_plan
from .opaf import canonical_hash
from .prototype_export_only import _members, _zip, _validated_log, validate_offline
from forms2apex.native_behavior import render_behavior_package

SCOPE = 'fox-source-behavior-package-v1'
_FALSE = ('import_verified', 'runtime_verified', 'clean_schema_install_passed',
          'package_reimport_passed', 'technically_verified', 'business_behavior_accepted')


def _bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def apex_members(files):
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())
            if name.endswith('.apx') or name.startswith('.apex/')}


def prepare_behavior_package(documents, parent_zip, selected_unit_ids=None):
    """Rebuild source authority locally; never accept caller-authored behavior IR."""
    plan = build_behavior_plan(documents, parent_zip, selected_unit_ids)
    if not plan['operations']:
        raise ValueError('No complete supported behavior is available for generation.')
    rendered, receipt = render_behavior_package(parent_zip, plan)
    if receipt['plan_sha256'] != plan['plan_sha256']:
        raise ValueError('Behavior generation is not bound to its exact source plan.')
    files = _members(rendered)
    parent = _members(parent_zip)
    for name in ('metadata.json', 'remediation.json', 'source-to-page.json', 'README.md'):
        archived = 'fox-package/parent/' + name
        if archived in files:
            raise ValueError('Parent evidence archive already exists.')
        files[archived] = parent['fox-package/' + name]
    previous = json.loads(parent['fox-package/metadata.json'])
    renderer_receipt_path = 'fox-package/behavior-receipt.json'
    embedded_receipt = json.loads(files[renderer_receipt_path])
    compatibility = deepcopy(previous['compatibility'])
    compatibility['parent_renderer_template'] = compatibility.pop('renderer_template')
    compatibility['behavior_renderer'] = {'scope': receipt['scope'],
                                          'sources': receipt['renderer_sources']}
    generated = {row['source_unit_id']: row for row in receipt['generated_operations']}
    remediation = deepcopy(json.loads(parent['fox-package/remediation.json']))
    for row in remediation:
        if row.get('code') == 'code_unit_not_translated' and row.get('code_unit_id') in generated:
            row.update(code='behavior_generated_runtime_pending',
                reason='Executable behavior was generated and wired with explicit web adaptations; runtime and business verification remain pending.',
                generation_status='generated_wired_adapted',
                next_action='Review the generated behavior and its lifecycle adaptations, then verify it in an approved target.')
    coverage = receipt['coverage']
    counts = {status: sum(row['status'] == status for row in coverage)
              for status in sorted({row['status'] for row in coverage})}
    metadata = {'schema_version': 1, 'scope': SCOPE,
        'status': 'GENERATED_FORMAT_VALIDATION_PENDING', 'data_mode': previous['data_mode'],
        'source_binding': plan['source_binding'], 'parent_zip_sha256': plan['parent_zip_sha256'],
        'parent_metadata_sha256': hashlib.sha256(parent['fox-package/metadata.json']).hexdigest(),
        'plan_sha256': plan['plan_sha256'], 'renderer_receipt_sha256': canonical_hash(embedded_receipt),
        'renderer_receipt_path': renderer_receipt_path,
        'source_parser_rebuilt': True, 'format_validated': False, 'validation': None,
        'parent_validation_applies': False, 'parent_AI_reviews_apply_to': 'original mapping only',
        'native_apex_generated': True, 'selected_code_scope': previous['selected_code_scope'],
        'behavior_coverage': {'total': len(coverage), 'counts': counts},
        'generated_operations': receipt['generated_operations'], 'adaptations': plan['adaptations'],
        'compatibility': compatibility, 'prerequisites': previous['prerequisites'],
        'omissions': remediation, **{name: False for name in _FALSE}}
    trace = {'schema_version': 1, 'scope': 'fox-behavior-source-to-target-v1',
        'source_binding': plan['source_binding'], 'parent_trace_sha256': plan['parent_trace_sha256'],
        'parent_trace_path': 'fox-package/parent/source-to-page.json',
        'generated_operations': receipt['generated_operations'], 'coverage': coverage,
        'runtime_verified': False, 'business_behavior_accepted': False}
    files['fox-package/metadata.json'] = _bytes(metadata)
    files['fox-package/remediation.json'] = _bytes(remediation)
    files['fox-package/source-to-page.json'] = _bytes(trace)
    files['fox-package/behavior-coverage.json'] = _bytes(coverage)
    files['fox-package/README.md'] = (
        '# Source-derived behavior package\n\n'
        'CURRENT format status is in metadata.json. Parent validation and AI reviews '
        'are historical evidence under parent/ and do not validate this derivative.\n\n'
        'Generated operations are listed in behavior-receipt.json and source-to-page.json. '
        'The numeric guard uses an explicit Continue button instead of a Forms keyboard '
        'event. Repeated Forms messages use one APEX notification. Its linked page '
        'loads existing synthetic row values, validates input and moves focus; it does '
        'not save values or implement the complete bag workflow. Report calculations '
        'operate on persisted synthetic rows, not an unsaved Forms record buffer.\n\n'
        'All source code units remain in behavior-coverage.json. Unsupported behavior, '
        'parent mapping/dependency findings, runtime testing and business acceptance '
        'remain outstanding. No target schema or application was imported by generation.\n\n'
        'Preserve the full project including .apex when extracting. Review supporting-schema.sql '
        'and remediation.json before any separately authorized non-production import.\n'
    ).encode('utf-8')
    manifest = apex_members(files)
    metadata['apex_members'] = manifest
    files['fox-package/metadata.json'] = _bytes(metadata)
    candidate = _zip(files)
    return candidate, {'plan': plan, 'renderer_receipt': receipt,
        'candidate_sha256': hashlib.sha256(candidate).hexdigest(), 'apex_members': manifest,
        'format_validated': False, 'runtime_verified': False, 'business_behavior_accepted': False}


def _seal_validated_behavior_package(candidate, bound_validation, validation_directory):
    """Attach fresh compiler evidence; generated APEX member bytes cannot change."""
    if bound_validation.get("candidate_sha256") != hashlib.sha256(candidate).hexdigest():
        raise ValueError("Compiler evidence belongs to another candidate.")
    checked = _validated_log(validation_directory, bound_validation["validation"])
    files = _members(candidate)
    metadata = json.loads(files['fox-package/metadata.json'])
    if (metadata.get('scope') != SCOPE or metadata.get('format_validated') is not False
            or metadata.get('validation') is not None or metadata.get('parent_validation_applies') is not False
            or any(metadata.get(name) is not False for name in _FALSE)
            or metadata.get('apex_members') != apex_members(files)):
        raise ValueError('Behavior candidate metadata or generated APEX content changed.')
    evidence = {'schema_version': 1, 'scope': 'fox-behavior-format-validation-v1',
        'candidate_sha256': hashlib.sha256(candidate).hexdigest(),
        'apex_members': apex_members(files), 'validation': checked,
        'runtime_verified': False, 'business_behavior_accepted': False}
    metadata.update(status='GENERATED_FORMAT_VALIDATED_RUNTIME_UNVERIFIED',
                    format_validated=True, validation=checked)
    files['fox-package/metadata.json'] = _bytes(metadata)
    files['fox-package/behavior-validation.json'] = _bytes(evidence)
    output = _zip(files)
    if apex_members(_members(output)) != evidence['apex_members']:
        raise ValueError('Validated APEX bytes changed during package publication.')
    return output, {**evidence, 'package_sha256': hashlib.sha256(output).hexdigest(),
                    'package_bytes': len(output)}


def validate_behavior_package(candidate, validation_directory, *, validator=None):
    """Run the compiler on these exact bytes and bind its result before sealing.

    A validator override is for explicit synthetic tests; the CLI always uses
    the configured real SQLcl /nolog implementation.
    """
    candidate = bytes(candidate)
    digest = hashlib.sha256(candidate).hexdigest()
    validation = (validator or validate_offline)(candidate, validation_directory)
    bound = {'candidate_sha256': digest, 'validation': validation}
    return _seal_validated_behavior_package(candidate, bound, validation_directory)
