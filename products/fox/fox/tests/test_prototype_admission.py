"""Local source admission tests; no model, database or browser execution."""
import pytest

from fox.prototype_admission import describe_prototype_sources, prepare_prototype_admission


def documents():
    return [('demo.xml', b'<FormModule Name="DEMO"><Block Name="MAIN" DatabaseBlock="true">'
             b'<Item Name="VALUE" ItemType="Text Item" DatabaseItem="true"/>'
             b'<Trigger Name="SAVE" TriggerText="BEGIN MISSING_API.SAVE; END;"/>'
             b'</Block></FormModule>')]


def arguments():
    description = describe_prototype_sources(documents())
    return dict(expected_source_binding=description['source_binding'],
                approved_chunk_hashes={row['id']: row['sha256'] for row in description['chunks']},
                target_profile_sha256='a' * 64, approved_redacted_source=True,
                approved_external_ai=True, approved_prototype_scope=True)


def test_complex_dependency_is_assessable_not_claimed_converted():
    description = describe_prototype_sources(documents())
    assert description['code_unit_count'] == 1
    assert description['processing_approved'] is False
    assert 'MISSING_API' not in str(description)
    result = prepare_prototype_admission(documents(), **arguments())
    assert result['summary']['selected_code_unit_count'] == 1
    assert result['summary']['business_behavior_accepted'] is False
    assert result['prototype']['source_binding'] == description['source_binding']


@pytest.mark.parametrize('name', ['approved_redacted_source', 'approved_external_ai', 'approved_prototype_scope'])
@pytest.mark.parametrize('value', [False, None, 1, 'true'])
def test_explicit_approval_required(name, value):
    args = arguments()
    args[name] = value
    with pytest.raises(ValueError, match='Confirm'):
        prepare_prototype_admission(documents(), **args)


def test_stale_source_rejected():
    args = arguments()
    changed = [('demo.xml', documents()[0][1].replace(b'VALUE', b'CHANGED'))]
    with pytest.raises(ValueError, match='Source binding'):
        prepare_prototype_admission(changed, **args)


def test_stale_chunk_rejected():
    args = arguments()
    args['approved_chunk_hashes'] = {next(iter(args['approved_chunk_hashes'])): 'b' * 64}
    with pytest.raises(ValueError, match='chunk hash'):
        prepare_prototype_admission(documents(), **args)


@pytest.mark.parametrize('target', ['', 'X' * 64, None, 'a' * 63])
def test_destination_binding_required(target):
    args = arguments()
    args['target_profile_sha256'] = target
    with pytest.raises(ValueError, match='destination'):
        prepare_prototype_admission(documents(), **args)


def test_empty_selection_stays_metadata_only():
    args = arguments()
    args['approved_chunk_hashes'] = {}
    result = prepare_prototype_admission(documents(), **args)
    assert result['summary']['metadata_only'] is True
    assert result['summary']['selected_code_unit_count'] == 0


@pytest.mark.parametrize('name,raw', [('../demo.xml', b'<FormModule/>'), ('demo.fmb', b'raw binary'),
                                    ('demo.xml', b'<broken>')])
def test_unsafe_or_nonxml_input_rejected(name, raw):
    with pytest.raises(ValueError):
        describe_prototype_sources([(name, raw)])
