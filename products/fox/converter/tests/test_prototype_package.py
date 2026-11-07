"""Pure package facade parity; no execution or target access."""
import importlib.util

import pytest

from forms2apex import prototype_package as package, prototype_release as release
from forms2apex import project_reviews, review_receipts, security


@pytest.mark.parametrize('name', ['RUNTIME_SCOPE', 'PACKAGE_SCOPE', 'runtime_binding',
    'expected_runtime_pages', '_package_zip', '_package_members', 'validate_prototype_package'])
def test_release_keeps_original_package_api(name):
    assert getattr(release, name) is getattr(package, name)


@pytest.mark.parametrize('value', [{}, {'z': '\u2603', 'a': [True, False, None, 12, 1.5]}])
def test_pure_canonical_hash_matches_original(value):
    assert package.canonical(value) == project_reviews.canonical(value)
    assert package.digest(value) == project_reviews.digest(value)


@pytest.mark.parametrize('job', ['fox-' + 'a' * 20, 'Abc-123_x', 'a' * 48, 'abc', 'ab',
                                  '../abc', 'abc/def', 'a' * 49, '_abc', 'abc\n'])
def test_pure_alias_has_exact_existing_semantics(job):
    try:
        expected = security.alias_for_job(job)
    except ValueError:
        with pytest.raises(ValueError):
            package.alias_for_job(job)
    else:
        assert package.alias_for_job(job) == expected


def test_duplicate_json_rejection_matches_original():
    pairs = [('a', 1), ('a', 2)]
    for unique in (package._unique_keys, review_receipts._unique_keys):
        with pytest.raises(ValueError, match='Duplicate JSON fields'):
            unique(pairs)


def test_pure_module_does_not_import_converter_execution_modules(monkeypatch):
    import builtins
    original = builtins.__import__
    forbidden = {'sqlcl', 'runtime_preflight', 'project_reviews', 'review_receipts',
                 'native_target', 'security', 'subprocess', 'http', 'socket'}
    def checked(name, globals=None, locals=None, fromlist=(), level=0):
        if name.rsplit('.', 1)[-1] in forbidden or forbidden.intersection(fromlist or ()):
            raise AssertionError('Pure package module imported an execution dependency: ' + name)
        return original(name, globals, locals, fromlist, level)
    monkeypatch.setattr(builtins, '__import__', checked)
    spec = importlib.util.spec_from_file_location('forms2apex._pure_package_probe', package.__file__)
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)
