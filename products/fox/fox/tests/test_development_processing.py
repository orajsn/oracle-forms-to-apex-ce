"""Synthetic exact-source development consent; no provider, DB or credentials."""
from copy import deepcopy
import hashlib

import pytest

from fox.development_processing import (POLICY_ID, describe_development_processing,
    prepare_development_processing, validate_development_processing)
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import describe_prototype_sources, prepare_prototype_admission
from fox.prototype_job import validate_prototype_snapshot


def documents():
    return [('a.xml', b'\xef\xbb\xbf<FormModule Name="FIRST"><Block Name="MAIN">'
            b'<Trigger Name="SAVE" TriggerText="BEGIN APP.SAVE(123, &apos;Keep Me&apos;); END;"/>'
            b'</Block></FormModule>'),
            ('b.xml', b'<FormModule Name="SECOND"><Block Name="OTHER">'
            b'<Item Name="VALUE" ItemType="Text Item"/></Block></FormModule>')]


def source_hash(docs):
    return hashlib.sha256('\n'.join(name + ':' + hashlib.sha256(raw).hexdigest()
        for name, raw in sorted(docs)).encode()).hexdigest()


def context(docs=None):
    docs = documents() if docs is None else docs
    provenance = [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                   'policy_id': 'fox-development-source-v1' if i == 0 else 'ordinary-intake',
                   'receipt_sha256': 'b' * 64 if i == 0 else None}
                  for i, (name, raw) in enumerate(sorted(docs))]
    return describe_development_processing(docs, project_id='synthetic-project',
        selected_source_set_id='ss-' + '1' * 32, source_hash=source_hash(docs),
        source_provenance=provenance, target_profile_sha256='a' * 64,
        delivery_mode='apexlang_package')


def arguments(docs=None):
    docs = documents() if docs is None else docs
    description = describe_prototype_sources(docs)
    chunks = {row['id']: row['sha256'] for row in description['chunks']}
    binding = prepare_development_processing(docs, context=context(docs), approved_chunk_hashes=chunks)
    return dict(expected_source_binding=description['source_binding'], approved_chunk_hashes=chunks,
        target_profile_sha256='a' * 64, approved_redacted_source=False,
        approved_unredacted_development_source=True, approved_external_ai=True,
        approved_prototype_scope=True, delivery_mode='apexlang_package',
        processing_mode='development', development_processing=binding)


def snapshot(*, legacy=False):
    docs = documents()
    args = arguments(docs)
    if legacy:
        for key in ('processing_mode', 'development_processing', 'approved_unredacted_development_source'):
            args.pop(key)
        args['approved_redacted_source'] = True
    selected = prepare_prototype_admission(docs, **args)['prototype']
    return {'project': 'synthetic-project', 'project_id': 'synthetic-project',
        'project_name': 'Synthetic prototype', 'selected_source_set_id': 'ss-' + '1' * 32,
        'source_hash': source_hash(docs), 'conversion_profile': 'native-blueprint-prototype-v1',
        'files': [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                   'text': raw.decode('utf-8-sig')} for name, raw in docs],
        'prototype': selected, 'approvals': {'owner': 'synthetic-owner', 'approved_at': 3.0,
            'redacted_source': legacy, 'external_ai': True, 'synthetic_prototype': True,
            **({} if legacy else {'unredacted_development_source': True})}}


def test_exact_multi_form_source_and_code_are_preserved_without_rewriting():
    value = snapshot()
    before = deepcopy(value)
    assert validate_prototype_snapshot(value) == documents()
    assert value == before
    binding = value['prototype']['development_processing']
    assert binding['policy_id'] == POLICY_ID
    assert binding['approved_chunk_hashes'] == value['prototype']['approved_chunk_hashes']
    assert value['prototype']['development_processing_sha256'] == canonical_hash(binding)
    assert 'Keep Me' not in str(binding) and 'APP.SAVE' not in str(binding)
    assert len(binding['source_provenance']) == 2


def test_legacy_snapshot_and_rebuild_keep_old_semantics_and_shape():
    value = snapshot(legacy=True)
    before = deepcopy(value)
    assert validate_prototype_snapshot(value) == documents()
    assert value == before
    assert 'processing_mode' not in value['prototype']
    assert 'unredacted_development_source' not in value['approvals']
    assert value['approvals']['redacted_source'] is True


def test_context_digest_is_selection_independent_but_full_consent_is_not():
    docs, base = documents(), context()
    full = arguments()['development_processing']
    metadata = prepare_development_processing(docs, context=base, approved_chunk_hashes={})
    assert canonical_hash(full) != canonical_hash(metadata)
    assert {key: value for key, value in full.items() if key != 'approved_chunk_hashes'} == base
    assert prepare_prototype_admission(docs, **arguments())['summary']['metadata_only'] is False


def test_bindings_do_not_alias_mutable_caller_values():
    docs, base = documents(), context()
    chunks = arguments()['approved_chunk_hashes']
    bound = prepare_development_processing(docs, context=base, approved_chunk_hashes=chunks)
    original = deepcopy(bound)
    base['source_provenance'][0]['receipt_sha256'] = 'c' * 64
    chunks.clear()
    assert bound == original


@pytest.mark.parametrize('key,value', [
    ('approved_redacted_source', True), ('approved_redacted_source', None),
    ('approved_redacted_source', 0), ('approved_unredacted_development_source', False),
    ('approved_unredacted_development_source', None), ('approved_unredacted_development_source', 1),
    ('approved_external_ai', False), ('approved_prototype_scope', False),
    ('processing_mode', 'redacted'), ('processing_mode', ''), ('processing_mode', 1),
    ('processing_mode', None), ('delivery_mode', None), ('delivery_mode', 'legacy'),
    ('development_processing', None), ('target_profile_sha256', 'c' * 64)])
def test_development_admission_rejects_ambiguous_or_stale_consent(key, value):
    args = arguments()
    args[key] = value
    with pytest.raises(ValueError):
        prepare_prototype_admission(documents(), **args)


@pytest.mark.parametrize('field,value', [
    ('schema_version', True), ('schema_version', 2), ('policy_id', 'unknown'),
    ('processing_mode', 'legacy'), ('source_binding', 'c' * 64),
    ('source_hash', 'c' * 64), ('project_id', '../bad'),
    ('selected_source_set_id', 'unknown'), ('target_profile_sha256', 'invalid'),
    ('delivery_mode', None)])
def test_context_derivation_is_strict(field, value):
    base = context()
    base[field] = value
    with pytest.raises(ValueError):
        prepare_development_processing(documents(), context=base, approved_chunk_hashes={})


@pytest.mark.parametrize('change', ['missing', 'extra', 'unsorted', 'name', 'source',
    'unknown-policy', 'no-development', 'missing-receipt', 'ordinary-receipt', 'extra-field'])
def test_provenance_covers_every_original_and_known_receipt_policy(change):
    base = context()
    provenance = base['source_provenance']
    if change == 'missing': provenance.pop()
    elif change == 'extra': provenance.append(deepcopy(provenance[0]))
    elif change == 'unsorted': provenance.reverse()
    elif change == 'name': provenance[0]['name'] = 'invented.xml'
    elif change == 'source': provenance[0]['sha256'] = 'c' * 64
    elif change == 'unknown-policy': provenance[0]['policy_id'] = 'unknown'
    elif change == 'no-development': provenance[0]['policy_id'] = 'fox-forms-redaction-v1'
    elif change == 'missing-receipt': provenance[0]['receipt_sha256'] = None
    elif change == 'ordinary-receipt': provenance[1]['receipt_sha256'] = 'c' * 64
    else: provenance[0]['raw_receipt'] = 'not allowed'
    with pytest.raises(ValueError):
        prepare_development_processing(documents(), context=base, approved_chunk_hashes={})


def test_mixed_legacy_prepared_and_development_sources_are_bound():
    base = context()
    base['source_provenance'][1].update(policy_id='fox-forms-redaction-v1', receipt_sha256='c' * 64)
    assert prepare_development_processing(documents(), context=base, approved_chunk_hashes={})


@pytest.mark.parametrize('change', ['project', 'source-set', 'source-hash', 'code', 'chunks',
    'target', 'receipt', 'binding-digest', 'mode', 'mode-strip', 'marker-strip', 'redacted',
    'export-mode', 'extra-binding-key', 'partial-binding', 'schema-bool'])
def test_snapshot_rejects_mode_downgrade_tamper_and_cross_context_reuse(change):
    value = snapshot()
    selected = value['prototype']
    if change == 'project': value.update(project='other-project', project_id='other-project')
    elif change == 'source-set': value['selected_source_set_id'] = 'ss-' + '2' * 32
    elif change == 'source-hash': value['source_hash'] = 'c' * 64
    elif change == 'code': value['files'][0]['text'] += ' '
    elif change == 'chunks': selected['approved_chunk_hashes'] = {}
    elif change == 'target': selected['target_profile_sha256'] = 'c' * 64
    elif change == 'receipt': selected['development_processing']['source_provenance'][0]['receipt_sha256'] = 'c' * 64
    elif change == 'binding-digest': selected['development_processing_sha256'] = 'c' * 64
    elif change == 'mode': selected['processing_mode'] = 'unknown'
    elif change == 'mode-strip':
        for key in ('processing_mode', 'development_processing', 'development_processing_sha256'): selected.pop(key)
        value['approvals']['redacted_source'] = True
    elif change == 'marker-strip': value['approvals'].pop('unredacted_development_source')
    elif change == 'redacted': value['approvals']['redacted_source'] = True
    elif change == 'export-mode': selected.pop('delivery_mode')
    elif change == 'extra-binding-key': selected['development_processing']['unexpected'] = True
    elif change == 'partial-binding': selected.pop('development_processing')
    else:
        selected['development_processing']['schema_version'] = True
        selected['development_processing_sha256'] = canonical_hash(selected['development_processing'])
    with pytest.raises(OpafError):
        validate_prototype_snapshot(value)


@pytest.mark.parametrize('change', ['marker', 'mode', 'binding'])
def test_legacy_snapshot_cannot_be_upgraded_with_development_markers(change):
    value = snapshot(legacy=True)
    if change == 'marker': value['approvals']['unredacted_development_source'] = False
    elif change == 'mode': value['prototype']['processing_mode'] = None
    else: value['prototype']['development_processing'] = arguments()['development_processing']
    with pytest.raises(OpafError):
        validate_prototype_snapshot(value)


def test_snapshot_rejects_resealed_binding_reused_for_different_target_or_selection():
    value = snapshot()
    selected = value['prototype']
    selected['development_processing']['target_profile_sha256'] = 'c' * 64
    selected['development_processing_sha256'] = canonical_hash(selected['development_processing'])
    with pytest.raises(OpafError):
        validate_prototype_snapshot(value)


def test_full_binding_validator_checks_optional_current_context():
    args = arguments()
    kwargs = dict(documents=documents(), approved_chunk_hashes=args['approved_chunk_hashes'],
        target_profile_sha256='a' * 64, delivery_mode='apexlang_package')
    assert validate_development_processing(args['development_processing'], **kwargs)
    with pytest.raises(ValueError):
        validate_development_processing(args['development_processing'], project_id='other-project', **kwargs)
