"""Pure negative/future-version boundaries; no runtime authority is fabricated."""
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from qa.operator import product_verifier as product


@pytest.mark.parametrize('version', [0, 4, 5, -1, True, False, '3', None])
def test_unknown_version_cannot_inherit_legacy_readiness(version):
    # Deliberately incomplete object: the rejection must precede all private
    # context, journal, reader and transport access.
    verifier = object.__new__(product.ProductVerifier)
    verifier.manifest = {'schema_version': version}
    verifier.hosted_admission = None
    with pytest.raises(product.ProductVerifierError, match='HOSTED_RELEASE_VERSION_UNSUPPORTED'):
        verifier._admission()


@pytest.mark.parametrize('version', [1, 2])
def test_known_legacy_dispatch_is_unchanged(version):
    verifier = object.__new__(product.ProductVerifier)
    verifier.manifest = {'schema_version': version}
    verifier.hosted_admission = None
    assert verifier._admission() == 'READY'
    verifier.hosted_admission = object()
    with pytest.raises(product.ProductVerifierError, match='HOSTED_ADMISSION_REQUIRES_V3'):
        verifier._admission()


@pytest.mark.parametrize('receipt', [None, [], {}, {'admission_state': None},
    {'admission_state': True}, {'admission_state': 'ATTENTION'},
    {'admission_state': 'ready'}, {'admission_state': 'READY '},
    {'admission_state': 1}, {'ready': True}])
def test_unrecognized_reader_state_is_not_ready(receipt):
    with pytest.raises(product.ProductVerifierError, match='HOSTED_ADMISSION_STATE_INVALID'):
        product.admission_state(receipt)


@pytest.mark.parametrize('state', ['READY', 'WAIT'])
def test_state_parser_returns_data_only(state):
    receipt = {'admission_state': state, 'automatic_replay_permitted': False}
    assert product.admission_state(receipt) == state
    assert receipt == {'admission_state': state, 'automatic_replay_permitted': False}
