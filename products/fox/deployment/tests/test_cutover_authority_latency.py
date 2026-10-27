"""Real capability delegation with synthetic owner/transport and virtual time.

No historical leases, OCI, SSH, service actions or archive data are used. These
tests prove duplicate-read/freshness behavior, not live cutover authority.
"""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
for directory in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from qa.operator import hosted_snapshot as snapshot
from qa.operator.preactivation_retirement import PreActivationRetirementContext
from qa.operator.tests.test_hosted_snapshot import config as synthetic_configuration

spec = importlib.util.spec_from_file_location('cutover_latency_under_test', ROOT / 'deployment/cutover_project_release.py')
cutover = importlib.util.module_from_spec(spec); spec.loader.exec_module(cutover)


def setup(monkeypatch, *, age=0, fail_owner=False):
    clock, reads, calls = [1000.0], [], []
    monkeypatch.setattr(snapshot.time, 'monotonic', lambda: clock[0])
    owner = object.__new__(PreActivationRetirementContext)
    owner.release = snapshot.G_RELEASE
    owner.current_raw = b'authored-synthetic-retained-release'
    def held():
        reads.append(clock[0])
        if fail_owner:
            raise RuntimeError('SYNTHETIC_LEASE_NO_LONGER_HELD')
        clock[0] += 16.0  # Recorded real retry reads took roughly 15–21 seconds.
    owner.require_active = held  # Explicit synthetic lease boundary only.
    def remote(*args, **kwargs):
        calls.append(clock[0])
        return b'{"status":"G_STOPPED_TLS_HELD","automatic_replay_permitted":false}'
    owner.components = SimpleNamespace(clean=SimpleNamespace(SSH=['synthetic-no-ssh'], run_process=remote))
    raw = snapshot.canonical(synthetic_configuration('pre-hosted-g'))
    authority = snapshot.CaptureAuthority(snapshot._KEY, raw, snapshot.sha(raw), owner, owner.current_raw)
    authority.issued -= age
    return owner, authority, clock, reads, calls


def execute(owner, authority):
    raw = cutover.canonical({'synthetic_plan_only': True})
    return cutover.execute_under_lock(owner, authority, plan_raw=raw, plan_sha256=cutover.sha(raw),
        installation_reference={'path':'/synthetic-private/installation.json','sha256':'a'*64},
        phase='stop', apply=True, expected_source_sha256=cutover.sha(Path(cutover.__file__).read_bytes()))


def test_real_capability_checks_owner_once_per_boundary_without_expiring_immediate_stop(monkeypatch):
    owner, authority, clock, reads, calls = setup(monkeypatch)
    assert execute(owner, authority)['status'] == 'G_STOPPED_TLS_HELD'
    assert calls == [1016.0]
    assert reads == [1000.0, 1016.0]
    assert clock[0] == 1032.0


def test_freshness_window_is_not_extended_to_hide_a_late_stop(monkeypatch):
    owner, authority, clock, reads, calls = setup(monkeypatch, age=31)
    with pytest.raises(cutover.CutoverError, match='FRESH_BASELINE_CAPTURE_AUTHORITY_REQUIRED'):
        execute(owner, authority)
    assert len(reads) == 1 and not calls


def test_actual_capability_still_requires_owner_validation_before_transport(monkeypatch):
    owner, authority, clock, reads, calls = setup(monkeypatch, fail_owner=True)
    with pytest.raises(RuntimeError, match='SYNTHETIC_LEASE_NO_LONGER_HELD'):
        execute(owner, authority)
    assert len(reads) == 1 and not calls
