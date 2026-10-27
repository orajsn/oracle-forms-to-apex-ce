"""Metadata integrity tests, not Oracle extraction or redaction attestation."""
import copy
import hashlib
import json

import pytest

from fox.extractor import ExtractionError, safe_name
from fox.intake import ALLOWED, MAX_FILE_BYTES, MAX_PROJECT_BYTES, checked_source, inventory
from fox.prepared_source import (
    MAX_MANIFEST_BYTES, UPLOAD_MANIFEST_NAME, PreparedSourceError,
    encode_upload_manifest, make_upload_manifest, parse_upload_manifest,
    verify_upload_manifest,
)


def checked(name='Demo.xml', raw=b'<Module><FormModule Name="DEMO"/></Module>'):
    return checked_source(name, raw)


def manifest():
    return make_upload_manifest('extract-1', [checked()])


def wire(value):
    return json.dumps(value).encode('utf-8')


def metadata(name='demo.txt', size=1):
    return {'name': name, 'sha256': 'a' * 64, 'bytes': size, 'text': 'x'}


def assert_safe_error(call):
    with pytest.raises(PreparedSourceError) as error:
        call()
    assert str(error.value) == 'Invalid prepared-source manifest or selected files.'
    assert len(str(error.value)) < 100


def test_contract_shape_and_hash_match_existing_inventory():
    files = [checked('z.xml'), checked('A.txt', b'notes\r\n')]
    value = make_upload_manifest('Extract_001-test', files)
    assert UPLOAD_MANIFEST_NAME == 'fox-readable-upload.json'
    assert set(value) == {'format', 'schema_version', 'extraction_job_id',
                          'readable_source_hash', 'files'}
    assert value['format'] == 'FOX-READABLE-UPLOAD'
    assert value['schema_version'] == 1
    assert value['readable_source_hash'] == inventory(files)['source_hash']
    assert [item['name'] for item in value['files']] == ['A.txt', 'z.xml']
    assert verify_upload_manifest(encode_upload_manifest(value), files) == value


def test_source_metadata_whitelist_and_no_aliasing():
    files = [dict(checked(), path='C:/private/customer', raw_input_map={'raw.fmb': 'Demo.xml'},
                  backend='private-tool', approved=True, timestamp='today')]
    value = make_upload_manifest('job', files)
    assert set(value['files'][0]) == {'name', 'sha256', 'bytes'}
    assert set(files[0]) != set(value['files'][0])
    raw = encode_upload_manifest(value)
    assert b'private' not in raw and b'approved' not in raw and b'<Module>' not in raw
    files[0]['name'] = 'changed.txt'
    assert value['files'][0]['name'] == 'Demo.xml'


@pytest.mark.parametrize('raw', [b'line\n', b'line\r\n', b'\xef\xbb\xbfline\r\n',
                               b'\xef\xbb\xbf<Module/>\r\n'])
def test_checked_source_preserves_original_bom_and_line_endings(raw):
    file = checked('source.txt', raw)
    value = make_upload_manifest('job', [file])
    assert value['files'][0]['sha256'] == hashlib.sha256(raw).hexdigest()
    assert value['files'][0]['bytes'] == len(raw)
    assert verify_upload_manifest(encode_upload_manifest(value), [file]) == value
    normalized = checked('source.txt', file['text'].replace('\r\n', '\n').encode())
    if raw != normalized['text'].encode():
        assert_safe_error(lambda: verify_upload_manifest(encode_upload_manifest(value), [normalized]))


def test_canonical_dedupes_formatting_keys_and_file_order():
    files = [checked('z.txt', b'z'), checked('A.txt', b'a')]
    value = make_upload_manifest('job', files)
    reordered = dict(reversed(list(value.items())))
    reordered['files'] = [dict(reversed(list(item.items()))) for item in reversed(value['files'])]
    styled = json.dumps(reordered, indent=4).encode()
    expected = encode_upload_manifest(value)
    assert encode_upload_manifest(parse_upload_manifest(styled)) == expected
    assert encode_upload_manifest(reordered) == expected
    assert encode_upload_manifest(make_upload_manifest('job', list(reversed(files)))) == expected
    assert parse_upload_manifest(styled) == value
    assert verify_upload_manifest(styled, list(reversed(files))) == value
    assert b'\n' not in expected and b': ' not in expected and not expected.startswith(b'\xef\xbb\xbf')


def test_canonical_does_not_mutate_input():
    value = manifest()
    original = copy.deepcopy(value)
    encode_upload_manifest(value)
    assert value == original


@pytest.mark.parametrize('job', ['', '-x', '_x', 'x' * 81, 'a/b', 'a\\b', 'a:b',
                                'a.b', 'a b', 'é', '\njob', None, True, 1, [], {}])
def test_job_id_rejected(job):
    assert_safe_error(lambda: make_upload_manifest(job, [checked()]))
    value = manifest()
    value['extraction_job_id'] = job
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('job', ['x', 'x' * 80, 'A_z-9'])
def test_job_id_boundaries(job):
    assert make_upload_manifest(job, [checked()])['extraction_job_id'] == job


@pytest.mark.parametrize('name', [
    '', '../demo.xml', 'a..xml', '/demo.xml', 'a/b.xml', 'a\\b.xml', 'a.xml:stream',
    'a:demo.xml', 'a.xml ', 'a.xml.', ' a.xml', '-a.xml', '_a.xml', '.a.xml',
    'a&b.xml', 'a"b.xml', 'a\tb.xml', 'a\nb.xml', 'é.xml', 'a\x00.xml',
    'CON.xml', 'con.SQL', 'PRN.txt', 'AUX.pld', 'NUL.xml', 'COM1.sql', 'COM9.pkb',
    'LPT1.xml', 'lpt9.txt', 'a' * 117 + '.xml', None, 4, True,
    UPLOAD_MANIFEST_NAME, UPLOAD_MANIFEST_NAME.upper(),
])
def test_unsafe_names_rejected_everywhere(name):
    file = metadata()
    file['name'] = name
    assert_safe_error(lambda: make_upload_manifest('job', [file]))
    value = manifest()
    value['files'][0]['name'] = name
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('name', ['CON.xml', 'LPT9.txt', 'a..xml', '-a.xml',
                                'a/b.xml', 'a\\b.xml', 'a.xml ', 'a.xml.', 'é.xml'])
def test_names_match_extractor_rejections(name):
    with pytest.raises(ExtractionError):
        safe_name(name)
    assert_safe_error(lambda: make_upload_manifest('job', [metadata(name)]))


@pytest.mark.parametrize('name', ['Demo.xml', 'a b-SOURCE_1.PLD', 'COM10.txt',
                                'CONs.xml', 'a' * 116 + '.xml'])
def test_names_match_extractor_acceptance(name):
    safe_name(name)
    assert make_upload_manifest('job', [metadata(name)])['files'][0]['name'] == name


@pytest.mark.parametrize('extension', sorted(ALLOWED))
def test_allowed_readable_extensions(extension):
    assert make_upload_manifest('job', [metadata('source' + extension)])['files']


@pytest.mark.parametrize('extension', ['.fmb', '.mmb', '.olb', '.pll', '.rdf', '.zip',
                                     '.tar', '.gz', '.7z', '.rar', '.exe', '.dll', '.json', ''])
def test_raw_binaries_archives_and_other_types_rejected(extension):
    assert_safe_error(lambda: make_upload_manifest('job', [metadata('source' + extension)]))


@pytest.mark.parametrize('size', [0, -1, MAX_FILE_BYTES + 1, 1.0, True, False, '1', None, [], {}])
def test_strict_byte_counts(size):
    assert_safe_error(lambda: make_upload_manifest('job', [metadata(size=size)]))
    value = manifest()
    value['files'][0]['bytes'] = size
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('digest', ['', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64,
                                   '0' * 63 + '\n', None, 1, True, [], {}])
def test_strict_sha256(digest):
    file = metadata()
    file['sha256'] = digest
    assert_safe_error(lambda: make_upload_manifest('job', [file]))
    value = manifest()
    value['files'][0]['sha256'] = digest
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))
    value = manifest()
    value['readable_source_hash'] = digest
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


def test_file_count_and_total_limits():
    assert_safe_error(lambda: make_upload_manifest('job', []))
    assert_safe_error(lambda: make_upload_manifest('job', [metadata(f'{i}.txt') for i in range(51)]))
    assert len(make_upload_manifest('job', [metadata(f'{i}.txt') for i in range(50)])['files']) == 50
    files = [metadata(f'{i}.txt', MAX_FILE_BYTES) for i in range(5)]
    assert sum(item['bytes'] for item in make_upload_manifest('job', files)['files']) == MAX_PROJECT_BYTES
    assert_safe_error(lambda: make_upload_manifest('job', files + [metadata('extra.txt')]))


@pytest.mark.parametrize('files', [None, {}, (), 'files', True, [None], [1], [[]], [{}],
                                  [{'name': 'a.txt', 'sha256': 'a' * 64}]])
def test_invalid_file_collections(files):
    assert_safe_error(lambda: make_upload_manifest('job', files))
    value = manifest()
    value['files'] = files
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('names', [('A.txt', 'a.txt'), ('a.txt', 'a.txt')])
def test_case_insensitive_deduplication(names):
    files = [metadata(name) for name in names]
    assert_safe_error(lambda: make_upload_manifest('job', files))
    value = manifest()
    value['files'] = [{k: v for k, v in file.items() if k != 'text'} for file in files]
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('field', ['format', 'schema_version', 'extraction_job_id', 'readable_source_hash', 'files'])
def test_missing_top_fields(field):
    value = manifest()
    value.pop(field)
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))
    assert_safe_error(lambda: encode_upload_manifest(value))


@pytest.mark.parametrize('extra', ['path', 'raw_input_map', 'backend', 'approvals', 'timestamp', 'text', 'source_hash'])
def test_unknown_top_fields_rejected(extra):
    value = manifest()
    value[extra] = 'C:/private/customer/source.fmb'
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))
    assert_safe_error(lambda: encode_upload_manifest(value))


@pytest.mark.parametrize('field', ['name', 'sha256', 'bytes'])
def test_missing_file_fields(field):
    value = manifest()
    value['files'][0].pop(field)
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))


@pytest.mark.parametrize('extra', ['text', 'path', 'raw', 'approved', 'backend'])
def test_unknown_declared_file_fields_rejected(extra):
    value = manifest()
    value['files'][0][extra] = 'C:/private/customer/source.fmb'
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))
    assert_safe_error(lambda: encode_upload_manifest(value))


@pytest.mark.parametrize('field,value', [('format', 'other'), ('format', 1), ('format', None),
    ('schema_version', True), ('schema_version', 1.0), ('schema_version', '1'),
    ('schema_version', 0), ('schema_version', 2), ('schema_version', None)])
def test_exact_format_version(field, value):
    changed = manifest()
    changed[field] = value
    assert_safe_error(lambda: parse_upload_manifest(wire(changed)))


def test_declared_combined_hash_must_match():
    value = manifest()
    value['readable_source_hash'] = '0' * 64
    assert_safe_error(lambda: parse_upload_manifest(wire(value)))
    assert_safe_error(lambda: encode_upload_manifest(value))


@pytest.mark.parametrize('change', ['missing', 'extra', 'case', 'renamed', 'sha', 'bytes'])
def test_verification_requires_exact_uploaded_set(change):
    files = [checked()]
    raw = encode_upload_manifest(make_upload_manifest('job', files))
    if change == 'missing':
        files = []
    elif change == 'extra':
        files.append(checked('extra.txt', b'notes'))
    elif change == 'case':
        files[0]['name'] = 'demo.xml'
    elif change == 'renamed':
        files[0]['name'] = 'Other.xml'
    elif change == 'sha':
        files[0]['sha256'] = '0' * 64
    else:
        files[0]['bytes'] += 1
    assert_safe_error(lambda: verify_upload_manifest(raw, files))


def test_verification_does_not_rehash_decoded_text_or_claim_content_trust():
    files = [checked(raw=b'\xef\xbb\xbf<Module/>\r\n')]
    raw = encode_upload_manifest(make_upload_manifest('job', files))
    files[0]['text'] = 'Upstream checked metadata, not decoded text, is this contract input.'
    verified = verify_upload_manifest(raw, files)
    assert set(verified) == {'format', 'schema_version', 'extraction_job_id', 'readable_source_hash', 'files'}
    assert all(set(item) == {'name', 'sha256', 'bytes'} for item in verified['files'])


@pytest.mark.parametrize('raw', [b'', b' ', b'null', b'true', b'1', b'[]', b'"value"',
    b'{', b'{} trailing', b'{"x":}', b'\xff', b'\xc0\xaf', b'\xef\xbb\xbf{}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b'[' * 1000 + b']' * 1000, b'{"x":{"y":{"z":[]}}}',
    b'{}\x00', rb'"\ud800"', None, '', bytearray(b'{}'), 1, True])
def test_malformed_json_and_wrong_raw_types(raw):
    assert_safe_error(lambda: parse_upload_manifest(raw))


def test_nonfinite_in_permitted_fields_rejected():
    raw = wire(manifest())
    size = str(manifest()['files'][0]['bytes']).encode()
    for token in (b'NaN', b'Infinity', b'-Infinity', b'1e999'):
        mutated = raw.replace(b'"bytes": ' + size, b'"bytes": ' + token)
        assert_safe_error(lambda: parse_upload_manifest(mutated))


def test_duplicate_keys_rejected_at_any_object_level():
    raw = wire(manifest())
    assert_safe_error(lambda: parse_upload_manifest(raw.replace(b'{', b'{"format":"FOX-READABLE-UPLOAD",', 1)))
    assert_safe_error(lambda: parse_upload_manifest(raw.replace(b'"bytes":', b'"name":"Demo.xml","bytes":', 1)))
    assert_safe_error(lambda: parse_upload_manifest(raw.replace(b'"schema_version":', b'"schema\\u005fversion":1,"schema_version":', 1)))


def test_public_metadata_size_limit_includes_whitespace():
    raw = encode_upload_manifest(manifest())
    at_limit = raw + b' ' * (MAX_MANIFEST_BYTES - len(raw))
    assert parse_upload_manifest(at_limit) == manifest()
    assert_safe_error(lambda: parse_upload_manifest(at_limit + b' '))


def test_maximum_valid_metadata_stays_bounded():
    files = [metadata(f'{i:02d}' + 'a' * 114 + '.txt') for i in range(50)]
    value = make_upload_manifest('x' * 80, files)
    assert len(encode_upload_manifest(value)) < MAX_MANIFEST_BYTES


@pytest.mark.parametrize('value', [None, [], True, 1, 'manifest'])
def test_encode_rejects_nonobject(value):
    assert_safe_error(lambda: encode_upload_manifest(value))
