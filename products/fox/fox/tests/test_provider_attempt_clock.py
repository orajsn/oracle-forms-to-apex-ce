"""SDK ISO timestamps carry microseconds; finer float fractions are not evidence."""
from fox.prototype_provider_reexecution import _epoch_microseconds


def test_same_microsecond_does_not_become_a_false_ordering_failure():
    consumed = 1794974138.3743563
    started = '2026-11-18T03:55:38.374356+00:00'
    assert _epoch_microseconds(consumed) == _epoch_microseconds(started)


def test_a_whole_microsecond_earlier_remains_earlier():
    consumed = 1794974138.3743563
    assert _epoch_microseconds('2026-11-18T03:55:38.374355+00:00') < _epoch_microseconds(consumed)
    assert _epoch_microseconds('2026-11-18T03:55:38.374357+00:00') > _epoch_microseconds(consumed)
