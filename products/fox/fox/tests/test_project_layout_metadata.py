"""Oracle-generated layout metadata must not prevent native project planning.

The synthetic XML mirrors the output of a real local Oracle 14c binary
roundtrip. It contains no customer code/data. No native tools, model, network
or database are used by these deterministic regressions.
"""
from copy import deepcopy
from pathlib import Path

import pytest

from fox.intake import checked_source, inventory
from fox.project_conversion import assess_project_conversion


FIXTURES = Path(__file__).parent / 'fixtures'


def sources():
    return [checked_source(name, (FIXTURES / name).read_bytes())
            for name in ('oracle-coordinate.xml', 'oracle-coordinate.sql')]


def assess(files):
    return assess_project_conversion(files, project_id='coordinate-regression',
        project_name='Synthetic coordinate regression', source_hash=inventory(files)['source_hash'])


def change_xml(text):
    files = sources()
    files[0] = checked_source(files[0]['name'], text.encode('utf-8'))
    return files


def codes(plan):
    return {finding['code'] for finding in plan['project_findings'] +
            [finding for form in plan['forms'] for finding in form['findings']]}


def test_oracle_generated_coordinate_is_not_a_conversion_blocker():
    files = sources()
    original = deepcopy(files)
    plan = assess(files)
    assert plan['state'] == 'READY'
    assert plan['can_generate'] is True and plan['summary']['blocking_findings'] == 0
    assert len(plan['rendering_spec']['forms']) == 1
    assert len(plan['rendering_spec']['forms'][0]['native_form']['columns']) == 5
    assert files == original  # No metadata stripping or rewriting to obtain READY.
    assert plan['source_hash'] == inventory(original)['source_hash']
    assert plan['forms'][0]['source_sha256'] == original[0]['sha256']
    assert plan['rendering_spec']['source_manifest_sha256'] == plan['source_hash']


@pytest.mark.parametrize('layout', [
    '<Coordinate/>',
    '<Coordinate CoordinateSystem="Character" CharacterCellWidth="8" CharacterCellHeight="16"/>',
    '<Coordinate RealUnit="Pixel" DefaultFontScaling="false"/>',
    '<Coordinate/><Canvas Name="MAIN"/><Window Name="MAIN"/>',
])
def test_known_desktop_layout_does_not_require_a_business_decision(layout):
    text = sources()[0]['text']
    start = text.index('<Coordinate ')
    end = text.index('/>', start) + 2
    plan = assess(change_xml(text[:start] + layout + text[end:]))
    assert plan['state'] == 'READY' and codes(plan) == set()


def test_coordinate_changes_stay_bound_to_the_source_version():
    original = sources()
    changed = change_xml(original[0]['text'].replace('RealUnit="Point"', 'RealUnit="Pixel"'))
    left, right = assess(original), assess(changed)
    assert left['state'] == right['state'] == 'READY'
    assert left['forms'][0]['native_form'] == right['forms'][0]['native_form']
    assert left['source_hash'] != right['source_hash']
    assert left['plan_sha256'] != right['plan_sha256']
    assert left['forms'][0]['source_sha256'] != right['forms'][0]['source_sha256']


@pytest.mark.parametrize(('extra', 'expected'), [
    ('<Trigger Name="ACTION" TriggerText="NULL;"/>', 'BUSINESS_CODE_REVIEW_REQUIRED'),
    ('<CustomRule Name="UNKNOWN"/>', 'UNMAPPED_FORMS_OBJECT'),
    ('<AttachedLibrary Name="MISSING_UTIL"/>', 'MISSING_DEPENDENCY'),
    ('<LOV Name="LOOKUP"/>', 'UNSUPPORTED_FORMS_OBJECT'),
])
def test_layout_support_does_not_hide_business_or_dependency_blockers(extra, expected):
    files = change_xml(sources()[0]['text'].replace('</FormModule>', extra + '</FormModule>'))
    plan = assess(files)
    assert plan['can_generate'] is False and plan['rendering_spec'] is None
    assert expected in codes(plan)


@pytest.mark.parametrize(('text', 'expected'), [
    ('<Coordinate Code="NULL;"/>', 'BUSINESS_CODE_REVIEW_REQUIRED'),
    ('<Coordinate>Unmapped behavior</Coordinate>', 'UNMAPPED_COORDINATE_CONTENT'),
    ('<Coordinate><CustomRule/></Coordinate>', 'UNMAPPED_COORDINATE_CONTENT'),
    ('<Coordinate xmlns="urn:not-oracle"/>', 'XML_NAMESPACE_UNSUPPORTED'),
    ('<Coordinate RealUnit="Point" realunit="Pixel"/>', 'AMBIGUOUS_XML_ATTRIBUTES'),
])
def test_coordinate_is_not_a_blanket_ignore_rule(text, expected):
    original = sources()[0]['text']
    start = original.index('<Coordinate ')
    end = original.index('/>', start) + 2
    plan = assess(change_xml(original[:start] + text + original[end:]))
    assert plan['can_generate'] is False
    assert expected in codes(plan)
