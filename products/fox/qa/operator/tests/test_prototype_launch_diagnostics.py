from qa.operator.prototype_browser import launch_diagnostics_allowed, ROOTLESS_V1_WARNING


def test_only_known_nonfatal_rootless_cgroup_warning_is_allowed():
    assert launch_diagnostics_allowed(b'')
    assert launch_diagnostics_allowed(ROOTLESS_V1_WARNING+b'\n')
    assert not launch_diagnostics_allowed(b'EACCES: permission denied')
    assert not launch_diagnostics_allowed(ROOTLESS_V1_WARNING+b'\nError: browser failed')
