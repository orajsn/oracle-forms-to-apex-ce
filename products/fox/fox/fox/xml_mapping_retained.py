"""Verify a completed XML mapping package against its saved generation evidence.

Caller MUST first authenticate the project owner and verify the original snapshot
and result JSON against their durable DB-event hashes. This reader authenticates
no standalone upload and grants no new generation, import or acceptance authority.
Fresh generation still rebuilds and validates against the current engine.
"""
from collections import Counter
from copy import deepcopy
import hashlib
import json
import re

from .forms_native_plan import POLICY_ID
from .prototype_export_only import _members, _validated_log
from . import xml_supporting_inputs

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


def _sources(files, metadata, manifest, snapshot, documents):
    """Check original bytes, not a reinterpretation by the installed XML parser."""
    _need(type(documents) is list and bool(documents)
          and type(snapshot['files']) is list and len(snapshot['files']) == len(documents))
    originals = {}
    for name, raw in documents:
        _need(type(name) is str and bool(name) and type(raw) is bytes and bool(raw)
              and name.casefold() not in {key.casefold() for key in originals})
        originals[name] = raw
    expected = [{'name': name, 'sha256': _sha(raw), 'bytes': len(raw)}
                for name, raw in sorted(originals.items())]
    saved = snapshot['files']
    _need(all(type(row) is dict and type(row.get('name')) is str
              and type(row.get('bytes')) is int for row in saved))
    _need(sorted(({key: row[key] for key in ('name', 'sha256', 'bytes')} for row in saved),
                 key=lambda row: row['name']) == expected)
    supporting = xml_supporting_inputs.retained(files,metadata,originals)
    if supporting:
        _need(supporting['selected_source_hash'] == snapshot['source_hash'])
        expected = [r for r in expected if r['name'].lower().endswith('.xml')]
        originals = {n:v for n,v in originals.items() if n.lower().endswith('.xml')}
    _need(bool(originals) and all(n.lower().endswith('.xml') for n in originals))
    _need(len({row['sha256'] for row in expected}) == len(expected))
    _need(manifest['files'] == expected
          and all(type(row['bytes']) is int for row in manifest['files']))
    _need({name for name in files if name.startswith('fox-package/sources/')} ==
          {'fox-package/sources/' + name for name in originals})
    for name, raw in originals.items():
        _need(files['fox-package/sources/' + name] == raw)


def _units(rows, chunks):
    """Use the sealed historical chunk inventory, never today's code-unit parser."""
    _need(type(rows) is list and len(rows) == len(chunks))
    identities, seen_chunks = {}, set()
    for row in rows:
        _need(type(row) is dict)
        unit, chunk = row['source_unit_id'], row['source_chunk_id']
        _need(type(unit) is str and bool(unit) and unit not in identities
              and type(chunk) is str and chunk in chunks and chunk not in seen_chunks
              and row['source_unit_sha256'] == chunks[chunk]
              and row['status'] in {'generated_wired_adapted', 'unsupported', 'missing_input'})
        identities[unit] = (chunk, row['source_unit_sha256'], row['status'])
        seen_chunks.add(chunk)
    _need(seen_chunks == set(chunks))
    return identities


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
    # The caller authenticated the immutable snapshot and exact candidate hash.
    # Preserve that original interpretation; a newer parser is not its authority.
    _need(type(snapshot['source_binding']) is str
          and re.fullmatch(r'[a-f0-9]{64}', snapshot['source_binding'])
          and snapshot['source_binding'] == metadata['source_binding']
          == manifest['source_binding'] == ledger['source_binding'])
    _sources(before, metadata, manifest, snapshot, documents)
    chunks = manifest['selected_chunk_hashes']
    _need(type(chunks) is dict and all(type(key) is str and bool(key)
          and type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value)
          for key, value in chunks.items()))
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
    coverage = _json(before['fox-package/behavior-coverage.json'])
    _need(_units(coverage, chunks) == _units(ledger['code_units'], chunks))
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
