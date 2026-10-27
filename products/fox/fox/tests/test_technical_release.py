"""Synthetic dispatcher tests. Readers are spies, not fabricated live proof.

Windows tests isolate only the pre-existing native path/ownership boundary to
this temporary test tree. Parsing, ZIP classification, hashes and routing run
unchanged; these tests make no POSIX ownership or Windows ACL assertion.
"""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import zipfile

import pytest

from fox import native_verification as native
from fox import technical_release as gate


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def package(members):
    members = {name: content if isinstance(content, bytes) else raw(content) for name, content in members.items()}
    if 'manifest.json' not in members:
        members['manifest.json'] = raw({name: hashlib.sha256(content).hexdigest() for name, content in members.items()})
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return stream.getvalue()


@pytest.fixture
def context(tmp_path, monkeypatch):
    root = tmp_path / 'fox-data'
    rid = 'fox-' + 'a' * 20
    job = root / 'jobs' / rid
    job.mkdir(parents=True)
    connection = sqlite3.connect(':memory:')
    connection.row_factory = sqlite3.Row
    connection.execute('CREATE TABLE technical_verifications(run TEXT PRIMARY KEY, proof_json TEXT)')
    run = {'id': rid, 'state': 'VERIFIED', 'source_hash': 'a' * 64, 'artifact': None}
    calls = []
    def bounded_test_path(path):
        path = Path(path).absolute()
        assert path == path.resolve(strict=True)
        assert path == tmp_path or tmp_path in path.parents
        for parent in (path, *path.parents):
            assert not parent.is_symlink()
            if parent == tmp_path:
                break
        return path
    monkeypatch.setattr(native, '_safe_path', bounded_test_path)
    checked = {'native': {'proof': {'scope': 'native-test-reader'}, 'package': b'native reader exact bytes'},
               'project': {'proof': {'scope': 'project-test-reader'}, 'package': b'project reader exact bytes'}}
    def native_reader(conn, directory, item):
        assert conn is connection and directory == root and item is run
        calls.append('native')
        return checked['native']
    def project_reader(conn, directory, item):
        assert conn is connection and directory == root and item is run
        calls.append('project')
        return checked['project']
    monkeypatch.setattr(native, 'checked_native_release', native_reader)
    monkeypatch.setitem(sys.modules, 'fox.project_verification_runtime', SimpleNamespace(checked_project_release=project_reader))
    yield SimpleNamespace(root=root, job=job, run=run, connection=connection, calls=calls, checked=checked)
    connection.close()


def put(context, name, value):
    path = context.job / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else raw(value))


def route(context):
    return gate.checked_release(context.connection, context.root, context.run)


def test_dispatcher_exports_the_unchanged_native_exception_boundary():
    assert gate.VerificationError is native.VerificationError


@pytest.mark.parametrize('profile,kind', [('native-table-form-v1', 'native'), ('native-project-v1', 'project')])
@pytest.mark.parametrize('location', ['source-snapshot.json', 'release-evidence.json', 'run', 'inventory'])
def test_known_profiles_route_without_reinterpreting_the_retained_reader(context, profile, kind, location):
    if location == 'run':
        context.run['conversion_profile'] = profile
    elif location == 'inventory':
        put(context, 'source-snapshot.json', {'inventory': {'conversion_profile': profile}})
    else:
        put(context, location, {'conversion_profile': profile})
    assert route(context) is context.checked[kind]
    assert context.calls == [kind]


@pytest.mark.parametrize('scope,kind', [
    ('fox-native-technical-verification-v1', 'native'),
    ('fox-native-technical-verification-v2', 'native'),
    ('fox-project-technical-verification-v1', 'project'),
])
@pytest.mark.parametrize('location', ['database', 'retained'])
def test_retained_proof_routes_even_when_snapshot_and_release_are_missing(context, scope, kind, location):
    proof = {'scope': scope}
    if location == 'database':
        context.connection.execute('INSERT INTO technical_verifications VALUES(?,?)', (context.run['id'], raw(proof).decode()))
    else:
        put(context, 'technical-verification/verification.json', proof)
    assert route(context) is context.checked[kind]
    assert context.calls == [kind]


@pytest.mark.parametrize('members,kind', [
    ({'native-project-spec.json': {'profile_id': 'native-project-v1'}}, 'project'),
    ({'source-to-apex.json': {'schema_version': 1, 'scope': 'fox-native-project-render-trace-v1'}}, 'project'),
    ({'source-to-apex.json': {'schema_version': 2, 'scope': 'fox-native-project-render-trace-v2'}}, 'project'),
    ({'evidence/project-review.json': {'fixture': True}}, 'project'),
    ({'evidence/form-reviews/form-' + 'a' * 20 + '.json': {'fixture': True}}, 'project'),
    ({'native-form-spec.json': {'profile_id': 'native-table-form-v1'}}, 'native'),
    ({'evidence/native-review.json': {'fixture': True}}, 'native'),
])
def test_native_package_markers_cannot_fall_through_after_metadata_removal(context, members, kind):
    put(context, 'apex-package.zip', package(members))
    assert route(context) is context.checked[kind]
    assert context.calls == [kind]


def test_omitted_project_member_still_declared_in_manifest_routes_project(context):
    put(context, 'apex-package.zip', package({'manifest.json': {'native-project-spec.json': 'a' * 64}}))
    assert route(context) is context.checked['project']
    assert context.calls == ['project']


@pytest.mark.parametrize('version,scope', [(None, 'fox-native-project-render-trace-v1'),
    (True, 'fox-native-project-render-trace-v1'), (1, 'fox-native-project-render-trace-v2'),
    (2, 'fox-native-project-render-trace-v1'), (3, 'fox-native-project-render-trace-v3')])
def test_unknown_or_mixed_trace_version_never_routes_as_supported(context, version, scope):
    put(context, 'apex-package.zip', package({'source-to-apex.json': {'schema_version': version, 'scope': scope}}))
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('content', [None, {}, {'scope': 'fox-project-technical-attempt-v1'}])
def test_partial_project_retention_alone_is_a_project_marker(context, content):
    retention = context.job / 'project-technical-verification'
    retention.mkdir()
    if content is not None:
        put(context, 'project-technical-verification/attempt.json', content)
    assert route(context) is context.checked['project']
    assert context.calls == ['project']


def test_project_pipeline_cache_alone_routes_to_project_reader(context):
    (context.job / 'native-project-pipeline').mkdir()
    assert route(context) is context.checked['project']
    assert context.calls == ['project']


@pytest.mark.parametrize('profile', ['native-table-form-v1', 'legacy-html-prototype-v1'])
@pytest.mark.parametrize('state', ['QA_REQUIRED', 'VERIFIED', 'ACCEPTED'])
def test_project_pipeline_cache_never_downgrades_conflicting_profile(context, profile, state):
    put(context, 'source-snapshot.json', {'conversion_profile': profile})
    (context.job / 'native-project-pipeline').mkdir()
    context.run['state'] = state
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('unsafe', ['file', 'broken_link'])
def test_unsafe_project_pipeline_cache_is_never_ignored(context, monkeypatch, unsafe):
    cache = context.job / 'native-project-pipeline'
    if unsafe == 'file':
        cache.write_bytes(b'not a directory')
    else:
        # Isolate the OS symlink observation on Windows, where creating one
        # can require privileges; all classifier decisions remain real.
        original = Path.is_symlink
        monkeypatch.setattr(Path, 'is_symlink', lambda path: path == cache or original(path))
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_project_specific_retained_proof_routes_without_snapshot_or_package(context):
    put(context, 'project-technical-verification/verification.json', {'scope': 'fox-project-technical-verification-v1'})
    assert route(context) is context.checked['project']
    assert context.calls == ['project']


@pytest.mark.parametrize('payload', [b'not JSON', {'scope': 'fox-native-technical-verification-v2'}])
def test_malformed_or_wrong_family_project_retained_proof_blocks(context, payload):
    put(context, 'project-technical-verification/verification.json', payload)
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def legacy(context, *, with_snapshot=True):
    if with_snapshot:
        put(context, 'source-snapshot.json', {'conversion_profile': 'legacy-html-prototype-v1'})
    members = {'evidence/migration-spec.json': {'template_id': 'sqlcl-26.1.2-fox-v1', 'prototype_html': '<p>Synthetic fixture</p>'},
        'evidence/release-evidence.json': {'conversion_profile': 'read-only-html-prototype'},
        'apexlang/application.apx': b'app SYNTHETIC ()',
        'apexlang/pages/p00000-global-page.apx': b'page 0 (\n name: Global Page\n)',
        'apexlang/pages/p00001-home.apx': b'page 1 (\n region fox-prototype (\n type: staticContent\n )\n)',
        'apexlang/pages/p09999-login.apx': b'page 9999 (\n name: Login Page\n)',
        'sql/f123.sql': b'-- synthetic historical fixture\nbegin\nwwv_flow_imp_page.create_page(p_id=>0,p_name=>\'Global Page\');\n'
                       b'wwv_flow_imp_page.create_page(p_id=>1,p_name=>\'Home\');\n'
                       b'wwv_flow_imp_page.create_page(p_id=>9999,p_name=>\'Login Page\');\nend;'}
    put(context, 'apex-package.zip', package(members))
    context.checked['native'] = None
    context.run['artifact'] = str(Path('jobs') / context.run['id'] / 'apex-package.zip')
    return members


@pytest.mark.parametrize('with_snapshot', [False, True])
def test_established_legacy_html_package_preserves_none_and_old_reader(context, with_snapshot):
    legacy(context, with_snapshot=with_snapshot)
    assert route(context) is None
    assert context.calls == ['native']


def test_unprofiled_legacy_snapshot_preserves_known_packaged_template(context):
    legacy(context)
    put(context, 'source-snapshot.json', {'files': [], 'source_hash': 'a' * 64})
    assert route(context) is None


@pytest.mark.parametrize('snapshot', [{}, {'conversion_profile': 'legacy-html-prototype-v1'}])
def test_missing_or_bare_legacy_metadata_is_not_a_downgrade_authority(context, snapshot):
    put(context, 'source-snapshot.json', snapshot)
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('where', ['snapshot', 'release', 'run', 'stored', 'retained', 'package'])
def test_unknown_profiles_and_proof_scopes_fail_closed(context, where):
    document = {'conversion_profile': 'native-project-v999'}
    if where == 'snapshot':
        put(context, 'source-snapshot.json', document)
    elif where == 'release':
        put(context, 'release-evidence.json', document)
    elif where == 'run':
        context.run.update(document)
    elif where == 'stored':
        context.connection.execute('INSERT INTO technical_verifications VALUES(?,?)', (context.run['id'], raw({'scope': 'future-proof'}).decode()))
    elif where == 'retained':
        put(context, 'technical-verification/verification.json', {'scope': 'future-proof'})
    else:
        put(context, 'apex-package.zip', package({'evidence/release-evidence.json': document}))
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('change', [
    lambda c: put(c, 'release-evidence.json', {'conversion_profile': 'native-table-form-v1'}),
    lambda c: c.run.update(conversion_profile='legacy-html-prototype-v1'),
    lambda c: put(c, 'technical-verification/verification.json', {'scope': 'fox-native-technical-verification-v2'}),
    lambda c: put(c, 'apex-package.zip', package({'native-form-spec.json': {'profile_id': 'native-table-form-v1'}})),
])
def test_conflicting_project_identity_blocks_both_readers(context, change):
    put(context, 'source-snapshot.json', {'conversion_profile': 'native-project-v1'})
    change(context)
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('state', ['REVIEW_REQUIRED', 'QA_REQUIRED', 'VERIFIED', 'ACCEPTED'])
def test_project_state_never_selects_legacy_fallback(context, state):
    put(context, 'source-snapshot.json', {'conversion_profile': 'native-project-v1'})
    context.run['state'] = state
    assert route(context) is context.checked['project']
    assert context.calls == ['project']


@pytest.mark.parametrize('kind,profile', [('native', 'native-table-form-v1'), ('project', 'native-project-v1')])
@pytest.mark.parametrize('result', [None, {}, {'proof': {}, 'package': ''}, {'proof': {}, 'package': b''}])
def test_native_and_project_readers_cannot_return_none_or_unchecked_output(context, kind, profile, result):
    put(context, 'source-snapshot.json', {'conversion_profile': profile})
    context.checked[kind] = deepcopy(result)
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == [kind]


@pytest.mark.parametrize('location,payload', [
    ('source-snapshot.json', b'{"conversion_profile":"legacy-html-prototype-v1","conversion_profile":"native-project-v1"}'),
    ('release-evidence.json', b'[]'),
    ('source-snapshot.json', b'{"native_project":null}'),
    ('source-snapshot.json', b'{"inventory":null}'),
    ('technical-verification/verification.json', b'not json'),
    ('apex-package.zip', b'not a zip'),
])
def test_malformed_identity_never_becomes_missing_legacy(context, location, payload):
    put(context, location, payload)
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('artifact', ['../outside.zip', '/outside.zip', 'jobs/other/apex-package.zip', '', 42])
def test_artifact_alias_or_traversal_is_not_a_release_identity(context, artifact):
    put(context, 'source-snapshot.json', {'conversion_profile': 'native-project-v1'})
    context.run['artifact'] = artifact
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


@pytest.mark.parametrize('change', [
    lambda c, m: m['evidence/migration-spec.json'].update(template_id='future-template'),
    lambda c, m: m.update({'schema/01_synthetic_schema.sql': b'-- not historical HTML'}),
    lambda c, m: m.update({'sql/f456.sql': b'-- extra app'}),
    lambda c, m: m.pop('apexlang/application.apx'),
    lambda c, m: m.update({'native-project-spec.json': {'profile_id': 'native-project-v1'}}),
    lambda c, m: m.update({'apexlang/pages/p00003-form-2.apx': b'page 3 (\n type: interactiveReport\n)'}),
    lambda c, m: m.update({'apexlang/pages/p00001-home.apx': b'page 1 (\n region data (\n type: form\n )\n)'}),
    lambda c, m: m.update({'apexlang/application.apx': b'app SYNTHETIC ()\npage 2 (\n name: Extra\n)'}),
    lambda c, m: m.update({'sql/f123.sql': m['sql/f123.sql'] + b'\nwwv_flow_imp_page.create_page(p_id=>2,p_name=>\'Extra\');'}),
    lambda c, m: m.update({'sql/f123.sql': m['sql/f123.sql'] + b"\nwwv_flow_imp_page.create_page_plug(p_plug_source_type=>'NATIVE_FORM');"}),
])
def test_legacy_package_must_remain_the_known_html_inventory(context, change):
    members = legacy(context)
    change(context, members)
    put(context, 'apex-package.zip', package(members))
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_legacy_with_orphaned_technical_attempt_cannot_downgrade(context):
    legacy(context)
    put(context, 'technical-verification/attempt.json', {'scope': 'fox-project-technical-attempt-v1'})
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_legacy_with_new_project_attempt_directory_cannot_downgrade(context):
    legacy(context)
    put(context, 'project-technical-verification/attempt.json', {'scope': 'fox-project-technical-attempt-v1'})
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_project_retention_as_regular_file_is_not_ignored(context):
    put(context, 'project-technical-verification', b'not a directory')
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_legacy_manifest_byte_tampering_blocks_before_old_reader(context):
    members = legacy(context)
    members['manifest.json'] = {name: '0' * 64 for name in members}
    put(context, 'apex-package.zip', package(members))
    with pytest.raises(native.VerificationError):
        route(context)
    assert context.calls == []


def test_dispatch_is_read_only_and_returns_the_original_checked_object(context):
    put(context, 'source-snapshot.json', {'conversion_profile': 'native-project-v1'})
    before = {str(path.relative_to(context.root)): path.read_bytes() for path in context.root.rglob('*') if path.is_file()}
    changes = context.connection.total_changes
    assert route(context) is context.checked['project']
    assert context.connection.total_changes == changes
    assert before == {str(path.relative_to(context.root)): path.read_bytes() for path in context.root.rglob('*') if path.is_file()}
