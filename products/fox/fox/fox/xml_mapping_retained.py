"""Read an older completed XML package after its mapping library has advanced.

Caller MUST first authenticate the project owner and verify the original snapshot
and result JSON against their durable DB-event hashes. This reader authenticates
no standalone upload and grants no new generation, import or acceptance authority.
Fresh generation still rebuilds and validates against the current engine.
"""
from collections import Counter
from copy import deepcopy
import hashlib
import json

from .forms_native_plan import POLICY_ID
from .forms_understanding_packet import _build
from .prototype_export_only import _members, _validated_log

_FALSE = ('schema_prepared', 'import_verified', 'runtime_verified',
          'clean_schema_install_passed', 'package_reimport_passed',
          'technically_verified', 'business_behavior_accepted')


def _need(value):
    if not value:
        raise ValueError('Retained XML source, catalog or package proof changed.')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _apex(files):
    return {name: _sha(raw) for name, raw in sorted(files.items())
            if name.endswith('.apx') or name.startswith('.apex/')}


def verify_retained_package(candidate, package, proof, snapshot, documents, validation_directory):
    """Verify original sealed evidence without executing any old or new generator."""
    expected_proof = {'schema_version', 'scope', 'candidate_sha256', 'apex_members',
                      'validation', 'runtime_verified', 'business_behavior_accepted',
                      'package_sha256', 'package_bytes'}
    _need(type(proof) is dict and set(proof) == expected_proof
          and proof['schema_version'] == 1 and type(proof['schema_version']) is int
          and proof['scope'] == 'fox-xml-format-validation-v1'
          and proof['runtime_verified'] is False and proof['business_behavior_accepted'] is False)
    _need(type(candidate) is bytes and type(package) is bytes
          and _sha(candidate) == proof['candidate_sha256']
          and _sha(package) == proof['package_sha256']
          and type(proof['package_bytes']) is int and len(package) == proof['package_bytes'])
    before, after = _members(candidate), _members(package)
    metadata = _json(before['fox-package/metadata.json'])
    manifest = _json(before['fox-package/source-manifest.json'])
    catalog = _json(before['fox-package/mapping-catalog.json'])
    ledger = _json(before['fox-package/mapping-ledger.json'])
    _need(all(type(value.get('schema_version')) is int and value['schema_version'] == 1
              for value in (metadata, manifest, catalog, ledger)))
    packet, chunks = _build(documents)
    _need(packet['source_binding'] == snapshot['source_binding'] == metadata['source_binding']
          == manifest['source_binding'] == ledger['source_binding'])
    expected_sources = [{key: entry['source'][key] for key in ('name', 'sha256', 'bytes')}
                        for entry in packet['sources']]
    _need(manifest['files'] == expected_sources)
    _need(manifest['selected_chunk_hashes'] == {c['id']: c['sha256'] for c in chunks})
    originals = dict(documents)
    for source in expected_sources:
        _need(before['fox-package/sources/' + source['name']] == originals[source['name']])
    _need(metadata['scope'] == 'fox-xml-mapping-package-v1'
          and metadata['origin'] == 'deterministic_local_xml'
          and metadata['data_mode'] == 'synthetic_test_only'
          and metadata['project_id'] == snapshot['project_id']
          and metadata['project_name'] == snapshot['project_name']
          and metadata['approved_policy_id'] == snapshot['policy_id'] == POLICY_ID
          and metadata['format_validated'] is False and metadata['validation'] is None
          and metadata['status'] == 'GENERATED_FORMAT_VALIDATION_PENDING'
          and metadata['source_parser_rebuilt'] is True
          and metadata['native_apex_generated'] is True
          and type(metadata['application_count']) is int and metadata['application_count'] == 1
          and type(metadata['provider_calls']) is int and metadata['provider_calls'] == 0
          and type(metadata['database_imports']) is int and metadata['database_imports'] == 0
          and metadata['ai_review'] == {'performed': False, 'approval_recorded': False, 'origin': 'none'}
          and all(metadata[name] is False for name in _FALSE))
    _need(catalog['catalog_id'] == 'fox-xml-mapping-catalog-v1'
          and type(catalog['revision']) is int and catalog['revision'] >= 1
          and catalog['catalog_sha256'] == _sha(_bytes({k:v for k,v in catalog.items() if k != 'catalog_sha256'}))
          and catalog['catalog_sha256'] == snapshot['catalog_sha256']
          == metadata['catalog_sha256'] == ledger['catalog_sha256']
          and catalog['implementation_sources'] == snapshot['implementation_sources'])
    expected_units = {c['code_unit_id']: c for c in chunks}
    coverage = _json(before['fox-package/behavior-coverage.json'])
    _need(type(coverage) is list and len(coverage) == len(expected_units)
          and {r['source_unit_id'] for r in coverage} == set(expected_units)
          and type(ledger['code_units']) is list and len(ledger['code_units']) == len(expected_units)
          and len({r['source_unit_id'] for r in ledger['code_units']}) == len(expected_units)
          and {r['source_unit_id'] for r in ledger['code_units']} == set(expected_units))
    for row in coverage + ledger['code_units']:
        unit = expected_units[row['source_unit_id']]
        _need(row['source_unit_sha256'] == unit['sha256'] and row['source_chunk_id'] == unit['id']
              and row['status'] in {'generated_wired_adapted', 'unsupported', 'missing_input'})
    _need({r['source_unit_id']:r['status'] for r in coverage} ==
          {r['source_unit_id']:r['status'] for r in ledger['code_units']})
    _need(metadata['behavior_coverage'] == {'total': len(coverage),
          'counts': dict(Counter(row['status'] for row in coverage))})
    _need(_apex(before) == proof['apex_members'] == _apex(after) == metadata['apex_members'])
    checked = _validated_log(validation_directory, proof['validation'])
    evidence = {key:proof[key] for key in expected_proof - {'package_sha256', 'package_bytes'}}
    _need(checked == proof['validation'] and 'fox-package/xml-validation.json' not in before)
    expected_meta = deepcopy(metadata)
    expected_meta.update(status='GENERATED_FORMAT_VALIDATED_RUNTIME_UNVERIFIED',
                         format_validated=True, validation=checked)
    _need(set(after) == set(before) | {'fox-package/xml-validation.json'})
    _need(after['fox-package/metadata.json'] == _bytes(expected_meta)
          and after['fox-package/xml-validation.json'] == _bytes(evidence))
    _need(all(after[name] == raw for name, raw in before.items() if name != 'fox-package/metadata.json'))
    return expected_meta, ledger, before
