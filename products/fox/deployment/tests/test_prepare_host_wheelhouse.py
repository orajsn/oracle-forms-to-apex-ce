"""Local-only wheel metadata/closure tests. No network, pip or installation."""
import base64
import csv
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import zipfile

import pytest


spec = importlib.util.spec_from_file_location("prepare_host_wheelhouse", Path(__file__).parents[1] / "prepare_host_wheelhouse.py")
tool = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tool
spec.loader.exec_module(tool)


def wheel(tmp_path, *, name="defusedxml", version="0.7.1", tag="py3-none-any", requires=(),
          python=">=3.8", metadata_name=None, tag_override=None, extra=None, bad_hash=False,
          directory=True, directory_content=b""):
    dist = name.replace("-", "_") + "-" + version + ".dist-info"
    metadata = "Metadata-Version: 2.1\nName: " + (metadata_name or name) + "\nVersion: " + version + "\nRequires-Python: " + python + "\n"
    metadata += "".join("Requires-Dist: " + value + "\n" for value in requires)
    entries = {name + "/__init__.py": b"# synthetic test module\n", dist + "/METADATA": metadata.encode(),
               dist + "/WHEEL": ("Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: " + (tag_override or tag) + "\n").encode()}
    if extra:
        entries.update(extra)
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for member, raw in entries.items():
        value = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        writer.writerow((member, "sha256=invalid" if bad_hash and member.endswith("__init__.py") else value, str(len(raw))))
    writer.writerow((dist + "/RECORD", "", ""))
    entries[dist + "/RECORD"] = record.getvalue().encode()
    path = tmp_path / f"{name.replace('-', '_')}-{version}-{tag}.whl"
    with zipfile.ZipFile(path, "w") as archive:
        if directory:
            archive.writestr(name + "/", directory_content)
        for member, raw in entries.items():
            info = zipfile.ZipInfo("placeholder")
            # Preserve malicious member spelling in the fixture even on
            # Windows, whose ZipInfo constructor normalizes backslashes.
            info.filename = member
            info.orig_filename = member
            archive.writestr(info, raw)
    return path


def test_safe_zero_byte_directory_entries_are_accepted(tmp_path):
    result = tool.wheel_metadata(wheel(tmp_path))
    assert result["record_integrity"] == "PASS"
    assert result["name"] == "defusedxml"
    assert result["members"] == 4


@pytest.mark.parametrize("tag", ["cp311-cp311-win_amd64", "cp311-abi3-manylinux_2_34_x86_64", "cp311-cp311-manylinux_2_28_aarch64"])
def test_incompatible_native_platform_rejected(tmp_path, tag):
    with pytest.raises(ValueError, match="WHEEL_TARGET_NOT_SUPPORTED"):
        tool.wheel_metadata(wheel(tmp_path, tag=tag))


@pytest.mark.parametrize("bad", ["../outside.py", "/absolute.py", "path\\bad.py", "C:bad.py", "defusedxml/__INIT__.py"])
def test_unsafe_or_case_colliding_members_rejected(tmp_path, bad):
    with pytest.raises(ValueError, match="WHEEL_MEMBER_UNSAFE"):
        tool.wheel_metadata(wheel(tmp_path, extra={bad: b"x"}))


def test_nonempty_directory_rejected(tmp_path):
    with pytest.raises(ValueError, match="WHEEL_DIRECTORY_HAS_CONTENT"):
        tool.wheel_metadata(wheel(tmp_path, directory_content=b"x"))


def test_record_digest_rechecked(tmp_path):
    with pytest.raises(ValueError, match="WHEEL_RECORD_HASH_MISMATCH"):
        tool.wheel_metadata(wheel(tmp_path, bad_hash=True))


def test_name_and_python_and_tag_must_match(tmp_path):
    for kwargs, code in [({"metadata_name": "other"}, "WHEEL_IDENTITY_MISMATCH"),
                         ({"python": ">=3.12"}, "WHEEL_PYTHON_UNSUPPORTED"),
                         ({"tag_override": "py2-none-any"}, "WHEEL_TAG_MISMATCH")]:
        with pytest.raises(ValueError, match=code):
            tool.wheel_metadata(wheel(tmp_path, **kwargs))


def test_linux_311_markers_and_inactive_extras(tmp_path):
    result = tool.wheel_metadata(wheel(tmp_path, requires=(
        'linuxdep>=1; sys_platform == "linux" and python_version == "3.11"',
        'winonly; sys_platform == "win32"',
        'optional[extra]; extra == "adk"')))
    assert result["active_requires_dist"] == ['linuxdep>=1; sys_platform == "linux" and python_version == "3.11"']


def test_active_url_extra_and_unobserved_os_markers_rejected(tmp_path):
    for requirement, code in [('thing[feature]>=1', "DEPENDENCY_URL_OR_EXTRAS_NOT_ALLOWED"),
            ('thing @ https://example.test/a.whl', "DEPENDENCY_URL_OR_EXTRAS_NOT_ALLOWED"),
            ('thing; platform_release == "4.18"', "DEPENDENCY_REQUIRES_UNOBSERVED_OS_DETAIL")]:
        with pytest.raises(ValueError, match=code):
            tool.wheel_metadata(wheel(tmp_path, requires=[requirement]))


def declared(name, version, deps=()):
    return {"name": name, "version": version, "active_requires_dist": list(deps)}


def test_complete_closure_and_exact_roots():
    values = [declared("oci", "2.188.0", ["dep>=2"]), declared("defusedxml", "0.7.1"), declared("dep", "2.0")]
    assert tool.dependency_closure(values) == ["defusedxml", "dep", "oci"]
    with pytest.raises(ValueError, match="ACTIVE_DEPENDENCY_UNSATISFIED"):
        tool.dependency_closure(values[:-1])
    with pytest.raises(ValueError, match="ACTIVE_DEPENDENCY_UNSATISFIED"):
        tool.dependency_closure(values[:-1] + [declared("dep", "1.0")])
    with pytest.raises(ValueError, match="UNRELATED_DISTRIBUTION_NOT_ALLOWED"):
        tool.dependency_closure(values + [declared("unrelated", "1")])
    with pytest.raises(ValueError, match="DUPLICATE_DISTRIBUTION"):
        tool.dependency_closure(values + [values[0]])


def test_wrong_root_version_never_accepted():
    with pytest.raises(ValueError, match="PINNED_ROOTS_MISSING"):
        tool.dependency_closure([declared("oci", "2.175.0"), declared("defusedxml", "0.7.1")])


def test_download_command_does_not_install_and_has_fixed_target(tmp_path):
    command = tool.download_command(tmp_path)
    assert "download" in command and "install" not in command
    assert "--only-binary=:all:" in command and "--no-cache-dir" in command
    assert "https://pypi.org/simple" in command
    assert command[-2:] == ["defusedxml==0.7.1", "oci==2.188.0"]
    assert all(platform in command for platform in tool.PLATFORMS)


def test_completed_output_is_never_overwritten(tmp_path):
    (tmp_path / "evidence.json").write_text("preserved")
    with pytest.raises(ValueError, match="UNPUBLISHED_DOWNLOAD_REQUIRED"):
        tool.verify_download(tmp_path)
    assert (tmp_path / "evidence.json").read_text() == "preserved"
