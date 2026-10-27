"""Offline contract tests; projection data never grants install or run authority."""
from collections import UserDict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from fox.installation import (
    FreshProjectionError,
    bind_projection,
    converter_port,
    parse_projection,
    projection_bytes,
    projection_sha256,
    validate_projection,
)


REPOSITORY = Path(__file__).resolve().parents[1]


def projection(**changes):
    return {
        'schema_version': 1,
        'scope': 'fox-fresh-app-projection-v1',
        'installation_mode': 'fresh',
        'installation_id': 'fst-' + '0123456789abcdef' * 2,
        'storage_plan_sha256': 'a' * 64,
        'storage_completion_sha256': 'b' * 64,
        'converter_endpoint': 'http://127.0.0.1:19091',
        **changes,
    }


def canonical(value):
    # Independent oracle: do not derive parser expectations from the producer.
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def bindings(value):
    return {key: value[key] for key in (
        'installation_id', 'storage_plan_sha256', 'storage_completion_sha256')}


def test_projection_round_trip_is_canonical_and_detached():
    original = projection()
    expected = canonical(original)
    validated = validate_projection(original)
    assert validated == original and validated is not original
    assert projection_bytes(original) == expected
    digest = hashlib.sha256(expected).hexdigest()
    assert projection_sha256(original) == digest
    parsed = parse_projection(expected, expected_sha256=digest)
    bound = bind_projection(original, **bindings(original))
    assert parsed == original and parsed is not original
    assert bound == original and bound is not original
    assert set(bound) == set(original)
    original['converter_endpoint'] = 'http://127.0.0.1:19092'
    assert validated['converter_endpoint'] == 'http://127.0.0.1:19091'
    assert parsed['converter_endpoint'] == bound['converter_endpoint']


def test_key_order_does_not_change_projection_bytes_or_hash():
    original = projection()
    reversed_order = dict(reversed(tuple(original.items())))
    assert projection_bytes(reversed_order) == canonical(original)
    assert projection_sha256(reversed_order) == hashlib.sha256(canonical(original)).hexdigest()


@pytest.mark.parametrize('value', [None, True, 1, [], (), 'projection', UserDict(projection())])
def test_non_object_projection_rejected(value):
    with pytest.raises(FreshProjectionError):
        validate_projection(value)


def test_object_subclasses_are_not_trusted_as_plain_projection_data():
    class DerivedDict(dict):
        def __iter__(self):
            pytest.fail('Do not inspect attacker-defined mapping behavior.')

    with pytest.raises(FreshProjectionError):
        validate_projection(DerivedDict(projection()))


@pytest.mark.parametrize('key', tuple(projection()))
def test_every_exact_field_is_required(key):
    value = projection()
    del value[key]
    with pytest.raises(FreshProjectionError):
        validate_projection(value)


@pytest.mark.parametrize('key,value', [
    ('schema_version', True), ('schema_version', 1.0), ('schema_version', '1'),
    ('schema_version', 0), ('schema_version', 2),
    ('scope', 'fox-fresh-app-projection-v2'), ('scope', None),
    ('installation_mode', 'legacy'), ('installation_mode', 'FRESH'),
    ('installation_id', 'fst-' + 'a' * 31),
    ('installation_id', 'fst-' + 'a' * 33),
    ('installation_id', 'fst-' + 'A' * 32),
    ('installation_id', 'fst-' + 'g' * 32),
    ('installation_id', 'fox-' + 'a' * 32),
    ('installation_id', 'fst-' + 'a' * 32 + '\n'),
    ('installation_id', 1),
    ('storage_plan_sha256', 'a' * 63),
    ('storage_plan_sha256', 'a' * 65),
    ('storage_plan_sha256', 'A' * 64),
    ('storage_plan_sha256', 'g' * 64),
    ('storage_plan_sha256', 'a' * 64 + '\n'),
    ('storage_plan_sha256', None),
    ('storage_completion_sha256', 'b' * 63),
    ('storage_completion_sha256', 'B' * 64),
    ('storage_completion_sha256', 'b' * 64 + ' '),
    ('storage_completion_sha256', []),
    ('converter_endpoint', None), ('converter_endpoint', 19091),
])
def test_wrong_types_and_noncanonical_field_values_rejected(key, value):
    with pytest.raises(FreshProjectionError):
        validate_projection(projection(**{key: value}))


@pytest.mark.parametrize('extra', [
    'data_dir', 'database_path', 'credential_file', 'converter_token', 'password',
    'ready', 'installed', 'accepted', 'verified', 'operation', 'authorization',
    'storage_plan', 'storage_completion', 'release_sha256', 'candidate_sha256',
    'runtime_sha256', 'deployment_sha256', 'admission_sha256',
    'C_sha256', 'R_sha256', 'F_sha256', 'D_sha256', 'A_sha256',
    'projection_sha256', 'unknown',
])
def test_extra_paths_credentials_readiness_and_authority_fields_rejected(extra):
    value = projection(**{extra: 'synthetic-not-authority'})
    for operation in (validate_projection, projection_bytes, projection_sha256):
        with pytest.raises(FreshProjectionError):
            operation(value)
    raw = canonical(value)
    with pytest.raises(FreshProjectionError):
        parse_projection(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(FreshProjectionError):
        bind_projection(value, **bindings(value))


@pytest.mark.parametrize('port', [1024, 8091, 19091, 65535])
def test_exact_loopback_endpoint_accepts_only_unprivileged_port_range(port):
    endpoint = f'http://127.0.0.1:{port}'
    assert converter_port(endpoint) == port
    assert validate_projection(projection(converter_endpoint=endpoint))['converter_endpoint'] == endpoint


@pytest.mark.parametrize('endpoint', [
    '', 'http://127.0.0.1', 'http://127.0.0.1:',
    'http://127.0.0.1:0', 'http://127.0.0.1:1023', 'http://127.0.0.1:65536',
    'http://127.0.0.1:-19091', 'http://127.0.0.1:+19091',
    'http://127.0.0.1:019091', 'http://127.0.0.1:01024',
    'http://127.0.0.1:19091/', 'http://127.0.0.1:19091/path',
    'http://127.0.0.1:19091?x=1', 'http://127.0.0.1:19091?',
    'http://127.0.0.1:19091#x', 'http://127.0.0.1:19091#',
    'https://127.0.0.1:19091', 'HTTP://127.0.0.1:19091',
    'http://localhost:19091', 'http://127.1:19091',
    'http://127.0.0.2:19091', 'http://0.0.0.0:19091',
    'http://2130706433:19091', 'http://0177.0.0.1:19091',
    'http://[::1]:19091', 'http://[::ffff:127.0.0.1]:19091',
    'http://127.0.0.1.example.test:19091', 'http://127.0.0.1.:19091',
    'http://u:p@127.0.0.1:19091', 'http://@127.0.0.1:19091',
    ' http://127.0.0.1:19091', 'http://127.0.0.1:19091 ',
    '\nhttp://127.0.0.1:19091', 'http://127.0.0.1:19091\n',
    'http://127.0.0.1:19\t091', 'http://127.0.0.1:１９０９１',
    'http://127.0.0.1:١٩٠٩١', 'http://127.0.0.1:19091\\path',
    None, True, 19091,
])
def test_endpoint_aliases_normalization_and_escaping_are_rejected(endpoint):
    with pytest.raises(FreshProjectionError):
        converter_port(endpoint)
    with pytest.raises(FreshProjectionError):
        validate_projection(projection(converter_endpoint=endpoint))


@pytest.mark.parametrize('digest', [None, True, '', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, '0' * 64])
def test_parse_requires_valid_matching_expected_hash(digest):
    with pytest.raises(FreshProjectionError):
        parse_projection(canonical(projection()), expected_sha256=digest)


def test_parse_rejects_changed_bytes_even_when_changed_projection_is_valid():
    original = canonical(projection())
    changed = canonical(projection(converter_endpoint='http://127.0.0.1:19092'))
    with pytest.raises(FreshProjectionError):
        parse_projection(changed, expected_sha256=hashlib.sha256(original).hexdigest())


@pytest.mark.parametrize('kind', ['text', 'bytearray', 'memoryview', 'none', 'object'])
def test_parser_requires_explicit_raw_bytes_without_coercion(kind):
    raw = canonical(projection())
    value = {'text': raw.decode(), 'bytearray': bytearray(raw),
             'memoryview': memoryview(raw), 'none': None, 'object': projection()}[kind]
    with pytest.raises(FreshProjectionError):
        parse_projection(value, expected_sha256=hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize('raw', [b' ' * 4097, b'[' * 1100 + b']' * 1100])
def test_parser_fails_closed_for_oversized_or_excessively_nested_input(raw):
    with pytest.raises(FreshProjectionError):
        parse_projection(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_invalid_projection_diagnostics_do_not_echo_supplied_secrets():
    marker = 'synthetic-secret-marker-not-a-credential'
    value = projection(converter_endpoint=f'http://{marker}@127.0.0.1:19091')
    for operation in (validate_projection, projection_bytes, projection_sha256):
        with pytest.raises(FreshProjectionError) as caught:
            operation(value)
        assert marker not in str(caught.value)


NONCANONICAL = [
    canonical(projection()).rstrip(b'\n'),
    canonical(projection()) + b'\n',
    b' ' + canonical(projection()),
    canonical(projection()).replace(b'\n', b'\r\n'),
    json.dumps(projection(), sort_keys=True, indent=2).encode() + b'\n',
    json.dumps(projection(), separators=(',', ':')).encode() + b'\n',
    canonical(projection()).replace(b'"fresh"', b'"fr\\u0065sh"'),
    canonical(projection()).replace(b'"schema_version":1', b'"schema_version":1.0'),
    b'\xef\xbb\xbf' + canonical(projection()),
    b'{"schema_version":1,"schema_version":1}\n',
    canonical(projection()).replace(b'{', b'{"schema_version":1,', 1),
    canonical(projection()).replace(b'{', b'{"schema_version":2,', 1),
    canonical(projection()) + b'{}',
    b'null\n', b'[]\n', b'{"bad":NaN}\n', b'{"bad":Infinity}\n',
    b'{"bad":-Infinity}\n', b'{"bad":"\xff"}\n', b'{', b'',
]


@pytest.mark.parametrize('raw', NONCANONICAL)
def test_parser_rejects_noncanonical_or_ambiguous_json_even_with_exact_hash(raw):
    with pytest.raises(FreshProjectionError):
        parse_projection(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize('key', tuple(bindings(projection())))
def test_binding_checks_each_context_identity_and_preserves_input(key):
    value = projection()
    before = canonical(value)
    expected = bindings(value)
    expected[key] = 'fst-' + 'f' * 32 if key == 'installation_id' else 'f' * 64
    with pytest.raises(FreshProjectionError):
        bind_projection(value, **expected)
    assert canonical(value) == before


@pytest.mark.parametrize('key', tuple(bindings(projection())))
@pytest.mark.parametrize('bad', [None, True, '', 'UPPERCASE', []])
def test_invalid_expected_binding_is_not_coerced(key, bad):
    value = projection()
    expected = {**bindings(value), key: bad}
    with pytest.raises(FreshProjectionError):
        bind_projection(value, **expected)


def test_import_and_all_projection_operations_are_inert_in_fresh_process(tmp_path):
    absent = tmp_path / 'must-not-be-created'
    program = r'''
import hashlib,json,os,pathlib,socket,sqlite3,subprocess,sys,threading,time,uuid
sys.path.insert(0,sys.argv[1])
root=pathlib.Path(os.environ['FOX_DATA_DIR'])
before=sorted(pathlib.Path.cwd().iterdir())
phase='import'
def forbidden(*args,**kwargs):
    raise AssertionError('PROJECTION_MUST_NOT_READ_STATE_WRITE_CONNECT_OR_START')
def audit(event,args):
    if event=='open':
        mode=args[1]
        flags=args[2]
        writing=(isinstance(mode,str) and any(c in mode for c in 'wax+')) or (
            isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if writing or phase=='pure': forbidden()
    if event.startswith(('socket.','sqlite3.','subprocess.')): forbidden()
    if event in {'os.mkdir','os.remove','os.rename','os.rmdir','os.system','os.chmod','os.link','os.symlink','os.truncate'}:
        forbidden()
    if phase=='pure' and event in {'os.listdir','os.scandir'}: forbidden()
sys.addaudithook(audit)
threading.Thread.start=forbidden
subprocess.Popen=forbidden
sqlite3.connect=forbidden
socket.create_connection=forbidden
socket.socket.connect=forbidden
import fox.installation as installation
assert 'fox.app' not in sys.modules
assert not root.exists()
assert sorted(pathlib.Path.cwd().iterdir())==before
value=json.loads(sys.argv[2])
expected=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
digest=hashlib.sha256(expected).hexdigest()
context={key:value[key] for key in ('installation_id','storage_plan_sha256','storage_completion_sha256')}
class NoEnvironment(dict):
    __getitem__=get=__iter__=items=__contains__=forbidden
os.environ=NoEnvironment()
os.getenv=forbidden
os.urandom=forbidden
time.time=forbidden
time.monotonic=forbidden
uuid.uuid4=forbidden
pathlib.Path.exists=forbidden
pathlib.Path.is_file=forbidden
pathlib.Path.is_dir=forbidden
pathlib.Path.stat=forbidden
phase='pure'
assert installation.validate_projection(value)==value
assert installation.projection_bytes(value)==expected
assert installation.projection_sha256(value)==digest
assert installation.parse_projection(expected,expected_sha256=digest)==value
assert installation.bind_projection(value,**context)==value
assert installation.converter_port(value['converter_endpoint'])==19091
assert 'fox.app' not in sys.modules
print(json.dumps({'app_imported':False,'state_created':False,'pure_operations':6}))
'''
    environment = {**os.environ, 'FOX_DATA_DIR': str(absent),
                   'FOX_VERIFICATION_ENABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run(
        [sys.executable, '-I', '-B', '-c', program, str(REPOSITORY), json.dumps(projection())],
        cwd=tmp_path, env=environment, capture_output=True, timeout=30, check=True)
    assert not result.stderr
    assert json.loads(result.stdout) == {
        'app_imported': False, 'state_created': False, 'pure_operations': 6}
    assert not absent.exists()
