"""Offline helper tests. No Java, SQLcl, database or network process starts."""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest


MODULE = Path(__file__).resolve().parents[1] / "validate_project_apexlang.py"
spec = importlib.util.spec_from_file_location("fox_offline_project_validator", MODULE)
validator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validator
spec.loader.exec_module(validator)


@pytest.fixture
def installation(tmp_path):
    home = tmp_path / "s"
    (home / "bin").mkdir(parents=True)
    (home / "lib").mkdir()
    names = ["dbtools-sqlcl.jar", "dbtools-apex.jar", "apexlang-compiler.jar", "dependency.jar"]
    for name in names:
        (home / "lib" / name).write_bytes(("synthetic-not-executable-" + name).encode())
    script = ('function setupCPLIST {\n' + ''.join(f'CPLIST="$SQL_HOME/lib/{name}:$CPLIST"\n' for name in names)
              + 'CPLIST="$SQL_HOME/../optional.jar:$CPLIST"\n'
              + '}\nif [ ! -z ${GRAALVM} ]; then\nfi\n'
              + validator.MAIN + '\n')
    (home / "bin/sql").write_text(script, encoding="utf-8")
    (home / "bin/dependencies.txt").write_text("Synthetic installed dependency listing", encoding="utf-8")
    java = tmp_path / "j/bin" / ("java.exe" if os.name == "nt" else "java")
    java.parent.mkdir(parents=True)
    java.write_bytes(b"synthetic-not-executable-java")
    inputs = tmp_path / "i/apexlang"
    (inputs / ".apex").mkdir(parents=True)
    (inputs / "pages").mkdir()
    (inputs / "application.apx").write_bytes(b"app EXAMPLE ()\n")
    (inputs / ".apex/apexlang.json").write_bytes(b'{"version":"26.1.0"}\n')
    (inputs / "pages/p00001-main.apx").write_bytes(b"page 1 ()\n")
    manifest = inputs.parent / "manifest.json"
    manifest.write_bytes(validator.canonical({"schema_version": 1, "files": {
        "apexlang/" + path.relative_to(inputs).as_posix(): validator.sha(path.read_bytes())
        for path in sorted(inputs.rglob("*")) if path.is_file()}}))
    return dict(sqlcl_home=home, java=java, input_dir=inputs, input_manifest=manifest,
                manifest_sha256=validator.sha(manifest.read_bytes()), evidence_dir=tmp_path / "e")


def no_process(*args, **kwargs):
    pytest.fail("This operation must not start any process")


def create_run_inputs(installation):
    run = installation["evidence_dir"] / "run"
    run.mkdir()
    for name in ("home", "tmp", "prefs", "appdata", "localappdata", "apexlang"):
        (run / name).mkdir()
    for source in installation["input_dir"].rglob("*"):
        if source.is_file():
            target = run / "apexlang" / source.relative_to(installation["input_dir"])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
    (run / "validate.sql").write_bytes(validator.validation_script(run / "apexlang"))
    return run


def test_prepare_hashes_tools_and_complete_input_without_spawning(installation, monkeypatch):
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    value = validator.prepare(**installation)
    assert value["status"] == "PREPARED_NOT_EXECUTED" and value["process_started"] is False
    assert value["input_file_count"] == 3 and value["jar_count"] == 4
    raw = Path(value["plan"]).read_bytes()
    plan = json.loads(raw)
    assert validator.sha(raw) == value["plan_sha256"]
    assert validator.load_plan(value["plan"], value["plan_sha256"]) == plan
    assert plan["installation"]["classpath"][-1].endswith("dbtools-sqlcl.jar")
    assert plan["installation"]["omitted_optional_classpath"] == ["../optional.jar"]
    assert plan["commands"]["version"][-1] == "-V"
    assert plan["commands"]["validation"][-4:-1] == ["-nohistory", "-S", "/nolog"]
    assert plan["commands"]["validation"][-1].endswith("run" + os.sep + "validate.sql")
    assert plan["stdin"] == {"mode": "EOF_PIPE", "bytes": 0}
    assert plan["database_connection_supplied"] is plan["import_permitted"] is plan["network_authorized"] is False
    assert {p.name for p in installation["evidence_dir"].iterdir()} == {"plan.json"}


@pytest.mark.parametrize("which", ["input", "manifest", "jar", "java", "helper", "command"])
def test_changed_approved_bytes_or_commands_block_before_process(installation, monkeypatch, which):
    prepared = validator.prepare(**installation)
    plan_path = Path(prepared["plan"])
    digest = prepared["plan_sha256"]
    if which == "input":
        (installation["input_dir"] / "application.apx").write_bytes(b"app CHANGED ()\n")
    elif which == "manifest":
        installation["input_manifest"].write_bytes(b'{"files":{}}')
    elif which == "jar":
        (installation["sqlcl_home"] / "lib/dependency.jar").write_bytes(b"changed")
    elif which == "java":
        installation["java"].write_bytes(b"changed")
    elif which == "helper":
        changed = installation["java"].parent / "changed-helper.py"
        changed.write_bytes(b"different-helper")
        monkeypatch.setattr(validator, "SELF", changed)
    else:
        plan = json.loads(plan_path.read_bytes())
        plan["commands"]["validation"] += ["connect", "do-not-log-this-secret"]
        raw = validator.canonical(plan)
        plan_path.write_bytes(raw)
        digest = validator.sha(raw)  # Even a new caller-supplied hash is not argv authority.
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    with pytest.raises(validator.ValidationError):
        validator.run(plan_path, digest)
    assert not (installation["evidence_dir"] / "run").exists()


def test_unlisted_or_missing_input_files_are_rejected(installation):
    path = installation["input_dir"] / "surprise.sql"
    path.write_bytes(b"not approved")
    with pytest.raises(validator.ValidationError, match="INPUT_MEMBERS_CHANGED"):
        validator.prepare(**installation)
    assert not installation["evidence_dir"].exists()
    path.unlink()
    (installation["input_dir"] / "application.apx").unlink()
    with pytest.raises(validator.ValidationError, match="INPUT_MEMBERS_CHANGED"):
        validator.prepare(**installation)


@pytest.mark.parametrize("name", ["../secret", "/absolute", "a/../b", "a//b", "./a", "a\\b", "C:secret", "a\nfile", "folder/"])
def test_manifest_path_traversal_and_noncanonical_names_rejected(installation, name):
    manifest = json.loads(installation["input_manifest"].read_bytes())
    manifest["files"][name] = "a" * 64
    raw = validator.canonical(manifest)
    installation["input_manifest"].write_bytes(raw)
    installation["manifest_sha256"] = validator.sha(raw)
    with pytest.raises(validator.ValidationError, match="MANIFEST_MEMBER_UNSAFE"):
        validator.prepare(**installation)
    assert not installation["evidence_dir"].exists()


def test_duplicate_json_field_and_case_alias_rejected(installation):
    with pytest.raises(validator.ValidationError, match="DUPLICATE_JSON_FIELD"):
        validator.json_object(b'{"files":{},"files":{}}')
    manifest = json.loads(installation["input_manifest"].read_bytes())
    manifest["files"]["APEXLANG/application.apx"] = manifest["files"]["apexlang/application.apx"]
    raw = validator.canonical(manifest)
    installation["input_manifest"].write_bytes(raw)
    installation["manifest_sha256"] = validator.sha(raw)
    with pytest.raises(validator.ValidationError, match="MANIFEST_IDENTITY_INVALID"):
        validator.prepare(**installation)


@pytest.mark.parametrize("location", ["input", "sqlcl"])
@pytest.mark.parametrize("name", ["login.sql", "GLOGIN.SQL"])
def test_startup_scripts_are_rejected_without_reading_them(installation, location, name):
    root = installation["input_dir"] if location == "input" else installation["sqlcl_home"]
    (root / name).write_bytes(b"do not execute or print")
    with pytest.raises(validator.ValidationError, match="STARTUP_SQL_FORBIDDEN"):
        validator.prepare(**installation)


@pytest.mark.parametrize("location", ["input", "child", "ancestor", "sqlcl"])
def test_evidence_and_input_runtime_directories_must_be_separate(installation, location):
    installation["evidence_dir"] = {
        "input": installation["input_dir"],
        "child": installation["input_dir"] / "out",
        "ancestor": installation["input_dir"].parent,
        "sqlcl": installation["sqlcl_home"] / "out",
    }[location]
    with pytest.raises(validator.ValidationError):
        validator.prepare(**installation)


@pytest.mark.parametrize("value", [0, -1, 601, True, "120", None])
def test_timeout_is_bounded_integer(installation, value):
    with pytest.raises(validator.ValidationError, match="TIMEOUT_BOUND_REQUIRED"):
        validator.prepare(**installation, timeout_seconds=value)


def test_existing_evidence_and_started_attempts_are_never_reused(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    raw = Path(prepared["plan"]).read_bytes()
    with pytest.raises(validator.ValidationError, match="EVIDENCE_ALREADY_EXISTS"):
        validator.prepare(**installation)
    (installation["evidence_dir"] / "run").mkdir()
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    with pytest.raises(validator.ValidationError, match="EXISTING_ATTEMPT_INSPECT_ONLY"):
        validator.run(prepared["plan"], prepared["plan_sha256"])
    assert Path(prepared["plan"]).read_bytes() == raw


def test_unknown_evidence_members_do_not_enter_sqlcl_startup(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    (installation["evidence_dir"] / "unlisted.txt").write_text("unlisted")
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    with pytest.raises(validator.ValidationError, match="EVIDENCE_MEMBERS_CHANGED"):
        validator.run(prepared["plan"], prepared["plan_sha256"])


def test_unsafe_paths_and_classpath_separators_fail_before_execution(tmp_path):
    for name in ('with"quote', "with\nnewline", "../outside", "//network/share", "bad" + os.pathsep + "classpath"):
        with pytest.raises(validator.ValidationError):
            validator.safe_path(tmp_path / name, exists=False)


def test_real_symlink_rejected_when_supported(installation):
    link = installation["input_dir"] / "linked.apx"
    try:
        link.symlink_to(installation["input_dir"] / "application.apx")
    except OSError:
        pytest.skip("This Windows test identity cannot create a synthetic symlink")
    with pytest.raises(validator.ValidationError, match="LINKED_PATH_FORBIDDEN"):
        validator.prepare(**installation)


def test_hardlinked_input_is_rejected(installation):
    original = installation["input_dir"] / "application.apx"
    link = installation["input_dir"].parent / "hardlink.apx"
    try:
        os.link(original, link)
    except OSError:
        pytest.skip("This filesystem cannot create a synthetic hardlink")
    with pytest.raises(validator.ValidationError, match="HARDLINK|BOUNDS"):
        validator.prepare(**installation)


def test_source_environment_cannot_supply_connection_or_java_options(installation, monkeypatch):
    for name in ("SQLPATH", "ORACLE_PATH", "ORACLE_HOME", "TNS_ADMIN", "CLASSPATH", "JAVA_TOOL_OPTIONS",
                 "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "OCI_CONFIG_FILE", "HTTP_PROXY", "PASSWORD", "HOME"):
        monkeypatch.setenv(name, "must-not-reach-child")
    paths = {key: str(value) for key, value in installation.items() if key != "manifest_sha256"}
    result = validator.child_environment(paths)
    assert not any(value == "must-not-reach-child" for value in result.values())
    assert not {"SQLPATH", "ORACLE_PATH", "ORACLE_HOME", "TNS_ADMIN", "CLASSPATH", "JAVA_TOOL_OPTIONS",
                "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "OCI_CONFIG_FILE", "HTTP_PROXY", "PASSWORD", "HOME"} & set(result)
    assert str(installation["evidence_dir"] / "run/home") == result["USERPROFILE"]


def test_fixed_script_has_only_validation_and_no_connection(installation):
    raw = validator.validation_script(installation["evidence_dir"] / "run/apexlang")
    text = raw.decode()
    assert text.count("apex validate -input ") == 1
    assert text.index("set define off") < text.index("apex validate -input")
    assert not any(word in text.casefold() for word in ("connect ", "apex import", "@http", "host ", "script "))
    assert text.splitlines()[-1] == "exit"


def test_an_actual_empty_pipe_delivers_eof_without_writing():
    read_fd, write_fd = os.pipe()
    class Process:
        stdin = os.fdopen(write_fd, "wb")
    process = Process()
    try:
        validator.close_stdin_eof(process)
        assert os.read(read_fd, 1) == b""
        assert process.stdin.closed
    finally:
        os.close(read_fd)


@pytest.mark.parametrize("code,text,expected", [
    (0, "Validation successful.\n", True),
    (0, "\n Validation successful. \n", True),
    (1, "Validation successful.\n", False),
    (True, "Validation successful.\n", False),
    (0, "", False),
    (0, "Error message says Validation successful. but failed", False),
    (0, "Validation successful.\nAPEXLang Compile Errors", False),
    (0, "Validation successful.\njava.io.IOException: failure", False),
    (0, "Validation successful.\nSEVERE wrong", False),
    (0, "Validation successful.\nORA-20001: failure", False),
    (0, "Connected to database\nValidation successful.\n", False),
    (0, "SQL>\nValidation successful.\n", False),
])
def test_marker_and_exit_are_both_required_without_errors_or_connections(code, text, expected):
    assert validator.successful_validation(code, text) is expected


class FakeChild:
    def __init__(self, *, stdout, stderr, output=b"", error=b"", running=False, exit_code=0):
        self.stdin = io.BytesIO()
        self.pid = 321
        self.returncode = None if running else exit_code
        self.exit_code = exit_code
        self.killed = False
        stdout.write(output); stdout.flush()
        stderr.write(error); stderr.flush()

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        assert timeout == 10
        if self.returncode is None:
            self.returncode = self.exit_code
        return self.returncode


def test_derived_commands_and_snapshot_are_used_for_one_complete_mocked_run(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    calls = []
    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["shell"] is False and kwargs["stdin"] is validator.subprocess.PIPE
        assert kwargs["cwd"] == installation["evidence_dir"] / "run"
        assert "TNS_ADMIN" not in kwargs["env"]
        text = b"SQLcl: Release 26.1.2.0 Production\n" if len(calls) == 1 else b"Validation successful.\n"
        return FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=text)
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    result = validator.run(prepared["plan"], prepared["plan_sha256"])
    assert result["passed"] is True and result["inputs_unchanged"] is result["snapshot_unchanged"] is True
    assert result["import_run"] is result["runtime_verified"] is result["human_acceptance_recorded"] is False
    assert len(calls) == 2 and calls[0][0][-1] == "-V"
    script = (installation["evidence_dir"] / "run/validate.sql").read_text()
    assert (installation["evidence_dir"] / "run/apexlang").as_posix() in script
    assert installation["input_dir"].as_posix() not in script
    for filename in ("version-exit.json", "validation-exit.json", "result.json"):
        assert (installation["evidence_dir"] / "run" / filename).is_file()
    assert result["validation_exit_receipt_sha256"] == validator.sha(
        (installation["evidence_dir"] / "run/validation-exit.json").read_bytes())


@pytest.mark.parametrize("mode", ["timeout", "output"])
def test_timeout_and_output_limit_only_kill_original_child(installation, monkeypatch, mode):
    prepared = validator.prepare(**installation, timeout_seconds=1)
    plan = validator.load_plan(prepared["plan"], prepared["plan_sha256"])
    run = create_run_inputs(installation)
    children = []
    def popen(argv, **kwargs):
        output = b"x" * (validator.MAX_STREAM + 1) if mode == "output" else b""
        child = FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=output, running=True)
        children.append(child)
        return child
    values = iter([0, 2])
    monkeypatch.setattr(validator.time, "monotonic", lambda: next(values))
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    with pytest.raises(validator.ValidationError, match="CHILD_LIMIT_OR_CONNECTION_UNCERTAINTY"):
        validator.child(plan, "validation", prepared["plan_sha256"])
    assert len(children) == 1 and children[0].killed and children[0].stdin.closed
    receipt = json.loads((run / "validation-exit.json").read_bytes())
    assert receipt["exit_code"] == -9 and receipt["exact_child_exit_observed"] is True
    assert receipt["stop_reason"] == ("TIMEOUT" if mode == "timeout" else "OUTPUT_LIMIT")


def test_internal_child_rejects_changed_argv_before_record_or_spawn(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    plan = validator.load_plan(prepared["plan"], prepared["plan_sha256"])
    plan["commands"]["validation"][-1] = "@unapproved.sql"
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    with pytest.raises(validator.ValidationError, match="FIXED_CHILD_ARGUMENTS_REQUIRED"):
        validator.child(plan, "validation", prepared["plan_sha256"])


def test_wrong_version_never_reaches_validation(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    calls = []
    def popen(argv, **kwargs):
        calls.append(argv)
        return FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=b"Release 99.0.0\n")
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    with pytest.raises(validator.ValidationError, match="SQLCL_VERSION_UNCONFIRMED"):
        validator.run(prepared["plan"], prepared["plan_sha256"])
    assert len(calls) == 1
    assert json.loads((installation["evidence_dir"] / "run/stopped.json").read_bytes())["code"] == "SQLCL_VERSION_UNCONFIRMED"
    assert not (installation["evidence_dir"] / "run/validation-intent.json").exists()


@pytest.mark.parametrize("kind", ["script", "snapshot", "startup", "original"])
def test_changes_after_version_stop_before_validation_dispatch(installation, monkeypatch, kind):
    prepared = validator.prepare(**installation)
    calls = []
    def popen(argv, **kwargs):
        calls.append(argv)
        run = installation["evidence_dir"] / "run"
        if kind == "script":
            (run / "validate.sql").write_bytes(b"connect forbidden\n")
        elif kind == "snapshot":
            (run / "apexlang/application.apx").write_bytes(b"app ALTERED ()\n")
        elif kind == "startup":
            (run / "home/login.sql").write_bytes(b"connect forbidden\n")
        else:
            (installation["input_dir"] / "application.apx").write_bytes(b"changed source")
        return FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=b"SQLcl: Release 26.1.2.0 Production\n")
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    with pytest.raises(validator.ValidationError):
        validator.run(prepared["plan"], prepared["plan_sha256"])
    assert len(calls) == 1
    assert not (installation["evidence_dir"] / "run/validation-intent.json").exists()


def test_argument_errors_do_not_echo_supplied_secret_or_start_process(monkeypatch, capsys):
    monkeypatch.setattr(validator.subprocess, "Popen", no_process)
    assert validator.main(["run", "--connection", "do-not-print-secret"]) == 3
    output = capsys.readouterr().out
    assert "ARGUMENTS_INVALID" in output and "do-not-print-secret" not in output


@pytest.mark.parametrize("marker,state", [(b"", "UNCONFIRMED"), (b"APEXLang Compile Errors\n", "INVALID"),
                                           (b"java.io.IOException: stopped\n", "UNCONFIRMED")])
def test_compiler_exit_zero_without_valid_success_is_not_a_pass(installation, monkeypatch, marker, state):
    prepared = validator.prepare(**installation)
    calls = []
    def popen(argv, **kwargs):
        calls.append(argv)
        text = b"SQLcl: Release 26.1.2.0 Production\n" if len(calls) == 1 else marker
        return FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=text)
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    result = validator.run(prepared["plan"], prepared["plan_sha256"])
    assert result["status"] == state and result["passed"] is False
    assert result["validation_exit_code"] == 0 and len(calls) == 2


def test_changed_child_evidence_is_not_silently_resealed(installation, monkeypatch):
    prepared = validator.prepare(**installation)
    calls = []
    def popen(argv, **kwargs):
        calls.append(argv)
        text = b"SQLcl: Release 26.1.2.0 Production\n" if len(calls) == 1 else b"Validation successful.\n"
        if len(calls) == 2:
            (installation["evidence_dir"] / "run/version.stdout").write_bytes(b"changed retained version log")
        return FakeChild(stdout=kwargs["stdout"], stderr=kwargs["stderr"], output=text)
    monkeypatch.setattr(validator.subprocess, "Popen", popen)
    with pytest.raises(validator.ValidationError, match="CHILD_EVIDENCE_CHANGED"):
        validator.run(prepared["plan"], prepared["plan_sha256"])
    assert not (installation["evidence_dir"] / "run/result.json").exists()


def test_bounded_walk_stops_before_enumerating_the_whole_directory(tmp_path, monkeypatch):
    for index in range(10):
        (tmp_path / f"file-{index}.apx").write_bytes(b"x")
    real_scandir = validator.os.scandir
    seen = []
    class LimitedScan:
        def __init__(self, path):
            self.iterator = real_scandir(path)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.iterator.close()
        def __iter__(self):
            return self
        def __next__(self):
            entry = next(self.iterator)
            seen.append(entry.name)
            assert len(seen) <= 3, "The bounded walker consumed beyond its rejection point"
            return entry
    monkeypatch.setattr(validator.os, "scandir", LimitedScan)
    with pytest.raises(validator.ValidationError, match="TREE_FILE_LIMIT"):
        validator.tree_files(tmp_path, maximum=2)
    assert len(seen) == 3


def test_reparse_directory_is_rejected_before_descent(tmp_path, monkeypatch):
    child = tmp_path / "reparse-child"
    child.mkdir()
    calls = []
    entry = SimpleNamespace(path=str(child), stat=lambda **kwargs: SimpleNamespace(
        st_mode=stat.S_IFDIR, st_file_attributes=0x400, st_nlink=1))
    class Scan:
        def __init__(self, path):
            calls.append(path)
            assert Path(path) == tmp_path, "Reparse entry must never be traversed"
        def __enter__(self):
            return iter([entry])
        def __exit__(self, *args):
            return None
    monkeypatch.setattr(validator.os, "scandir", Scan)
    with pytest.raises(validator.ValidationError, match="LINKED_PATH_FORBIDDEN"):
        validator.tree_files(tmp_path)
    assert calls == [tmp_path]


def test_jar_count_is_checked_before_reading_jar_bytes(installation, monkeypatch):
    real_tree, real_read = validator.tree_files, validator.read_regular
    actual = real_tree(installation["sqlcl_home"], maximum=5000)
    for index in range(1001):
        actual[f"lib/extra-{index}.jar"] = installation["sqlcl_home"] / f"lib/extra-{index}.jar"
    monkeypatch.setattr(validator, "tree_files", lambda *args, **kwargs: actual)
    def read(path, maximum=validator.MAX_JSON):
        assert Path(path).suffix != ".jar", "Oversized catalog must fail before reading any JAR"
        return real_read(path, maximum)
    monkeypatch.setattr(validator, "read_regular", read)
    with pytest.raises(validator.ValidationError, match="SQLCL_JAR_LIMIT"):
        validator.installation(installation["sqlcl_home"], installation["java"])


@pytest.mark.parametrize("token", ["26.1.2.0.1", "26.1.2.0-SNAPSHOT", "26.1.2.01", "26.1.2.0,", "26.1.3.0"])
def test_version_prefixes_are_not_the_exact_approved_version(token):
    assert validator.confirmed_version(0, "SQLcl: Release " + token + " Production\n") is False


def test_version_banner_cannot_hide_runtime_failure_or_multiple_versions():
    good = "SQLcl: Release 26.1.2.0 Production\n"
    assert validator.confirmed_version(0, good) is True
    assert validator.confirmed_version(0, good + "java.io.IOException: failure\n") is False
    assert validator.confirmed_version(0, good + good) is False
    assert validator.confirmed_version(1, good) is False


@pytest.mark.parametrize("code,text,state", [
    (0, "Validation successful.\n", "VALID"),
    (0, "APEXLang Compile Errors:\nInvalid page declaration", "INVALID"),
    (1, "APEXLang Compile Errors\nInvalid field type", "INVALID"),
    (1, "", "UNCONFIRMED"),
    (0, "java.io.IOException: Incorrect function", "UNCONFIRMED"),
    (0, "APEXLang Compile Errors\njava.lang.OutOfMemoryError", "UNCONFIRMED"),
    (0, "APEXLang Compile Errors\nValidation successful.\n", "UNCONFIRMED"),
])
def test_validation_classification_does_not_blame_source_for_tool_failure(code, text, state):
    assert validator.validation_verdict(code, text)[0] == state


def test_ampersand_evidence_path_uses_literal_sqlcl_input(installation):
    installation["evidence_dir"] = installation["evidence_dir"].parent / "R&D"
    result = validator.prepare(**installation)
    plan = validator.load_plan(result["plan"], result["plan_sha256"])
    text = validator.validation_script(Path(plan["paths"]["evidence_dir"]) / "run/apexlang").decode()
    assert "R&D" in text
    assert text.index("set define off") < text.index("apex validate -input")
