"""Prepare and execute one offline SQLcl APEXlang validation.

No database connection, import, model or network operation is provided. The
only child commands are the installed SqlCli version check and a fixed /nolog
validation script. Preparation is inert except for create-only local evidence.
Run requires the exact reviewed plan hash and never reuses a started attempt.

This is application-level command/environment isolation, not an OS network
sandbox. Use trusted installed Java/SQLcl and approved input; do not supply
credentials or customer data. An interrupted wrapper without exit evidence
must be inspected before another attempt, not treated as successful validation.
Java preference path properties do not prove Windows registry isolation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time


SELF = Path(__file__).resolve()
SQLCL_VERSION = "26.1.2.0"
MAIN = "oracle.dbtools.raptor.scriptrunner.cmdline.SqlCli"
PLAN_SCOPE = "fox-offline-project-validation-plan-v1"
SHA = re.compile(r"[a-f0-9]{64}\Z")
MAX_JSON = 2_000_000
MAX_INPUT_BYTES = 20_000_000
MAX_INPUT_FILES = 250
MAX_RUNTIME_BYTES = 1_000_000_000
MAX_STREAM = 2_000_000
MAX_TIMEOUT = 600
STOP_TEXT = re.compile(r"Connected to|Enter user.name|Enter password|SQL>|jdbc:(?:thin|oci)|ORA-(?:01017|12154|125\d\d)", re.I)
ERROR_TEXT = re.compile(r"APEXLang Compile Errors|Validation failed|\bORA-\d{5}\b|\bSP2-\d+\b|\bSEVERE\b|"
                        r"\b[A-Za-z0-9_.$]*(?:Exception|Error)\b", re.I)


class ValidationError(ValueError):
    """Fixed bounded codes only; no supplied paths, args or provider output."""


def need(ok, code):
    if not ok:
        raise ValidationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def json_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "DUPLICATE_JSON_FIELD")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("INVALID_JSON")))
    except (UnicodeError, json.JSONDecodeError):
        raise ValidationError("INVALID_JSON") from None
    need(type(value) is dict, "JSON_OBJECT_REQUIRED")
    return value


def safe_path(value, *, exists=True):
    need(isinstance(value, (str, Path)), "PATH_REQUIRED")
    text = str(value)
    need(text and not text.startswith(("\\\\", "//"))
         and not any(ord(char) < 32 or char == '"' for char in text)
         and ".." not in Path(text).parts, "UNSAFE_PATH")
    path = Path(os.path.abspath(text))
    need(not any(":" in part for part in path.parts[1:]), "ALTERNATE_STREAM_FORBIDDEN")
    need(not any(os.pathsep in part for part in path.parts[1:]), "CLASSPATH_SEPARATOR_PATH_FORBIDDEN")
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "LINKED_PATH_FORBIDDEN")
    need(not exists or path.exists(), "REQUIRED_PATH_MISSING")
    need(os.name != "nt" or len(str(path).encode("utf-16-le")) // 2 <= 259, "WINDOWS_PATH_TOO_LONG")
    return path


def read_regular(value, maximum=MAX_JSON):
    path = safe_path(value)
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
         "REGULAR_FILE_BOUNDS_REQUIRED")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need((before.st_dev, before.st_ino, before.st_size) == (opened.st_dev, opened.st_ino, opened.st_size),
             "FILE_CHANGED_ON_OPEN")
        raw = stream.read(maximum + 1)
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
         and len(raw) == before.st_size, "FILE_CHANGED_DURING_READ")
    return raw


def tree_files(root, *, maximum=MAX_INPUT_FILES):
    root = safe_path(root)
    need(root.is_dir(), "DIRECTORY_REQUIRED")
    files, pending, count = {}, [root], 0
    while pending:
        current = safe_path(pending.pop())
        # Reject reparse/link entries before descent. Do not materialize or
        # sort an unbounded recursive iterator merely to apply a later limit.
        with os.scandir(current) as entries:
            for entry in entries:
                count += 1
                need(count <= maximum * 4, "TREE_MEMBER_LIMIT")
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                     "LINKED_PATH_FORBIDDEN")
                safe_path(path)
                # Windows DirEntry's cached metadata can report st_nlink=0.
                # Query the path itself rather than treating that as a link
                # count or weakening the one-link requirement.
                info = path.lstat()
                need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                     "LINKED_PATH_FORBIDDEN")
                need(path.name.casefold() not in {"login.sql", "glogin.sql"}, "STARTUP_SQL_FORBIDDEN")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "SPECIAL_OR_HARDLINK_FORBIDDEN")
                need(len(files) < maximum, "TREE_FILE_LIMIT")
                files[path.relative_to(root).as_posix()] = path
    return dict(sorted(files.items()))


def member_name(name):
    need(type(name) is str and name and not any(ord(c) < 32 for c in name)
         and not any(token in name for token in ("\\", ":", "//"))
         and not name.startswith("/") and not name.endswith("/")
         and all(part not in ("", ".", "..") for part in name.split("/")), "MANIFEST_MEMBER_UNSAFE")
    return PurePosixPath(name)


def input_files(input_dir, manifest_path, expected_sha):
    root, manifest_path = safe_path(input_dir), safe_path(manifest_path)
    need(type(expected_sha) is str and SHA.fullmatch(expected_sha), "MANIFEST_SHA_REQUIRED")
    need(root.is_dir() and manifest_path.parent in root.parents, "MANIFEST_MUST_BE_OUTSIDE_INPUT")
    raw = read_regular(manifest_path)
    need(sha(raw) == expected_sha, "INPUT_MANIFEST_CHANGED")
    manifest = json_object(raw)
    members = manifest.get("files")
    need(type(members) is dict and 1 <= len(members) <= 2000, "MANIFEST_FILES_REQUIRED")
    seen = set()
    for name, digest in members.items():
        member_name(name)
        need(name.casefold() not in seen and type(digest) is str and SHA.fullmatch(digest), "MANIFEST_IDENTITY_INVALID")
        seen.add(name.casefold())
    prefix = root.relative_to(manifest_path.parent).as_posix() + "/"
    expected = {name[len(prefix):]: digest for name, digest in members.items() if name.startswith(prefix)}
    need(1 <= len(expected) <= MAX_INPUT_FILES and {"application.apx", ".apex/apexlang.json"} <= set(expected),
         "APEXLANG_MANIFEST_REQUIRED")
    actual = tree_files(root)
    need(set(actual) == set(expected), "INPUT_MEMBERS_CHANGED")
    values, total = {}, 0
    for name, path in actual.items():
        need(PurePosixPath(name).suffix.lower() in {".apx", ".sql", ".json"}, "INPUT_FILE_TYPE_UNSUPPORTED")
        content = read_regular(path, MAX_INPUT_BYTES)
        total += len(content)
        need(total <= MAX_INPUT_BYTES and sha(content) == expected[name], "INPUT_BYTES_CHANGED_OR_TOO_LARGE")
        values[name] = content
    return {"manifest_sha256": expected_sha, "manifest_prefix": prefix,
            "file_sha256": dict(sorted(expected.items())), "file_count": len(expected), "bytes": total}, values


def installation(sqlcl_home, java):
    home, java = safe_path(sqlcl_home), safe_path(java)
    need(home.is_dir() and java.name.casefold() in {"java", "java.exe"}, "INSTALLED_JAVA_AND_SQLCL_REQUIRED")
    java_raw = read_regular(java, 30_000_000)
    launcher = read_regular(home / "bin/sql", 2_000_000)
    dependencies = read_regular(home / "bin/dependencies.txt", 2_000_000)
    # Scan names only outside the JAR catalog; no user profile or connection store.
    catalog = tree_files(home, maximum=5000)
    try:
        script = launcher.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError:
        raise ValidationError("SQLCL_LAUNCHER_ENCODING_INVALID") from None
    need("\r" not in script and script.count("function setupCPLIST {") == 1 and MAIN in script,
         "SQLCL_LAUNCHER_LAYOUT_UNSUPPORTED")
    block = script.split("function setupCPLIST {", 1)[1].split("\nif [ ! -z ${GRAALVM}", 1)[0]
    entries = re.findall(r'^CPLIST="\$SQL_HOME/(.+):\$CPLIST"$', block, re.M)
    need(bool(entries), "SQLCL_CLASSPATH_UNCONFIRMED")
    classpath, omitted = [], []
    for relative in reversed(entries):
        need(re.fullmatch(r"[A-Za-z0-9_./*+-]+", relative) is not None, "SQLCL_CLASSPATH_LAYOUT_UNSUPPORTED")
        if ".." in PurePosixPath(relative).parts:
            omitted.append(relative)
            continue
        candidates = ([path for name, path in catalog.items()
                       if path.parent == home / relative[:-1] and path.suffix == ".jar"]
                      if relative.endswith("*") else ([catalog[relative]] if relative in catalog else []))
        if not candidates:
            omitted.append(relative)
        for path in candidates:
            safe_path(path)
            need(path.is_relative_to(home / "lib") and path.suffix == ".jar", "CLASSPATH_OUTSIDE_SQLCL_LIB")
            if path not in classpath:
                classpath.append(path)
    win32 = catalog.get("lib/dbtools-win32.jar")
    if os.name == "nt" and win32 is not None and win32 not in classpath:
        safe_path(win32)
        classpath.append(win32)
    need({"dbtools-sqlcl.jar", "dbtools-apex.jar", "apexlang-compiler.jar"} <= {path.name for path in classpath},
         "SQLCL_APEX_COMPILER_REQUIRED")
    jar_paths = {name: path for name, path in catalog.items()
                 if name.startswith("lib/") and path.suffix == ".jar"}
    need(1 <= len(jar_paths) <= 1000, "SQLCL_JAR_LIMIT")
    total = sum(path.stat().st_size for path in jar_paths.values())
    need(total <= MAX_RUNTIME_BYTES, "SQLCL_RUNTIME_SIZE_LIMIT")
    jars = {name: sha(read_regular(path, 100_000_000)) for name, path in jar_paths.items()}
    return {"java_sha256": sha(java_raw), "launcher_sha256": sha(launcher),
            "dependencies_sha256": sha(dependencies), "classpath": [str(path) for path in classpath],
            "jar_sha256": jars, "jar_bytes": total, "omitted_optional_classpath": omitted}


def java_argv(paths, installed):
    run = Path(paths["evidence_dir"]) / "run"
    return [paths["java"], "--enable-native-access=ALL-UNNAMED", "-Dpolyglot.engine.WarnInterpreterOnly=false",
        "-Djava.awt.headless=true", "-Dnashorn.args=--no-deprecation-warning", "-Dapple.awt.UIElement=true",
        "-Xms64M", "-Xmx2G", "-Xss100m", "-XX:+IgnoreUnrecognizedVMOptions",
        "--add-opens=java.prefs/java.util.prefs=ALL-UNNAMED", "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "-Dpolyglot.js.nashorn-compat=true", "-Doracle.sqlcl.skipOracleHome=true", "-Dsqlcl.home=" + paths["sqlcl_home"],
        "-Duser.home=" + str(run / "home"), "-Djava.io.tmpdir=" + str(run / "tmp"),
        "-Djava.util.prefs.userRoot=" + str(run / "prefs"), "-Duser.language=en", "-Duser.country=US",
        "-Dfile.encoding=UTF-8", "-Djava.net.useSystemProxies=false", "-Dhttp.proxyHost=127.0.0.1",
        "-Dhttp.proxyPort=9", "-Dhttps.proxyHost=127.0.0.1", "-Dhttps.proxyPort=9", "-Dhttp.nonProxyHosts=",
        "-DsocksProxyHost=127.0.0.1", "-DsocksProxyPort=9", "-DsocksNonProxyHosts=",
        "-client", "-cp", os.pathsep.join(installed["classpath"]), MAIN]


def validation_script(snapshot):
    value = str(snapshot.as_posix())
    need(not any(ord(c) < 32 or c == '"' for c in value), "VALIDATION_INPUT_PATH_INVALID")
    return ("set echo off\nset heading off\nset feedback off\nset verify off\nset define off\n"
            "whenever sqlerror exit failure rollback\n"
            f'apex validate -input "{value}"\nexit\n').encode("utf-8")


def command_argv(paths, installed, name):
    need(name in {"version", "validation"}, "FIXED_VALIDATION_STEP_REQUIRED")
    base = java_argv(paths, installed)
    if name == "version":
        return base + ["-V"]
    return base + ["-nohistory", "-S", "/nolog", "@" + str(Path(paths["evidence_dir"]) / "run/validate.sql")]


def build_plan(*, sqlcl_home, java, input_dir, input_manifest, manifest_sha256, evidence_dir, timeout_seconds=120):
    paths = {key: str(safe_path(value, exists=key != "evidence_dir")) for key, value in
             {"sqlcl_home": sqlcl_home, "java": java, "input_dir": input_dir,
              "input_manifest": input_manifest, "evidence_dir": evidence_dir}.items()}
    output = Path(paths["evidence_dir"])
    need(output.parent.is_dir() and output not in Path(paths["input_dir"]).parents
         and output != Path(paths["input_dir"]) and Path(paths["input_dir"]) not in output.parents
         and Path(paths["sqlcl_home"]) not in output.parents and Path(paths["java"]).parent not in output.parents,
         "SEPARATE_EVIDENCE_DIRECTORY_REQUIRED")
    need(type(timeout_seconds) is int and 1 <= timeout_seconds <= MAX_TIMEOUT, "TIMEOUT_BOUND_REQUIRED")
    inputs, _ = input_files(paths["input_dir"], paths["input_manifest"], manifest_sha256)
    installed = installation(paths["sqlcl_home"], paths["java"])
    run = output / "run"
    for name in inputs["file_sha256"]:
        safe_path(run / "apexlang" / name, exists=False)
    for name in ("validation-intent.json", "validation-exit.json", "validation.stdout", "exception-cleanup.json"):
        safe_path(run / name, exists=False)
    commands = {name: command_argv(paths, installed, name) for name in ("version", "validation")}
    need(os.name != "nt" or all(len(subprocess.list2cmdline(argv).encode("utf-16-le")) // 2 < 30000
                                for argv in commands.values()), "WINDOWS_COMMAND_TOO_LONG")
    return {"schema_version": 1, "scope": PLAN_SCOPE, "helper_sha256": sha(read_regular(SELF)),
            "host_platform": os.name, "paths": paths, "input": inputs, "installation": installed,
            "commands": commands, "script_sha256": sha(validation_script(run / "apexlang")),
            "version_timeout_seconds": 30, "validation_timeout_seconds": timeout_seconds,
            "expected_sqlcl_version": SQLCL_VERSION, "max_bytes_per_output_stream": MAX_STREAM,
            "stdin": {"mode": "EOF_PIPE", "bytes": 0}, "database_connection_supplied": False,
            "import_permitted": False, "network_authorized": False,
            "network_boundary": "Fixed offline commands and loopback proxies; not an OS network sandbox.",
            "preferences_boundary": "Fresh Java path properties; Windows registry isolation is not claimed.",
            "cleanup_boundary": "Original Popen handle while this helper runs; forced wrapper termination requires inspection."}


def save_new(path, value):
    path = safe_path(path, exists=False)
    raw = value if type(value) is bytes else canonical(value)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(**options):
    output = safe_path(options["evidence_dir"], exists=False)
    need(not output.exists(), "EVIDENCE_ALREADY_EXISTS")
    value = build_plan(**options)
    output.mkdir(mode=0o700)
    raw = canonical(value)
    save_new(output / "plan.json", raw)
    return {"status": "PREPARED_NOT_EXECUTED", "plan": str(output / "plan.json"),
            "plan_sha256": sha(raw), "input_file_count": value["input"]["file_count"],
            "jar_count": len(value["installation"]["jar_sha256"]), "process_started": False}


def load_plan(plan_path, expected_sha):
    path = safe_path(plan_path)
    need(path.name == "plan.json" and type(expected_sha) is str and SHA.fullmatch(expected_sha), "REVIEWED_PLAN_REQUIRED")
    raw = read_regular(path)
    need(sha(raw) == expected_sha, "PLAN_HASH_CHANGED")
    value = json_object(raw)
    need(value.get("scope") == PLAN_SCOPE and type(value.get("paths")) is dict
         and set(value["paths"]) == {"sqlcl_home", "java", "input_dir", "input_manifest", "evidence_dir"}
         and type(value.get("input")) is dict and "manifest_sha256" in value["input"]
         and path.parent == Path(value["paths"]["evidence_dir"]), "PLAN_PATH_BINDING_INVALID")
    current = build_plan(**value["paths"], manifest_sha256=value["input"]["manifest_sha256"],
                         timeout_seconds=value.get("validation_timeout_seconds"))
    need(canonical(current) == raw, "PLAN_INPUT_OR_TOOL_CHANGED")
    return current


def child_environment(paths):
    run, java = Path(paths["evidence_dir"]) / "run", Path(paths["java"])
    kept = {name: value for name, value in os.environ.items()
            if name.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE"}}
    path_parts = [str(java.parent)]
    if os.name == "nt":
        system_root = next((v for k, v in kept.items() if k.upper() == "SYSTEMROOT"), None)
        need(system_root and Path(system_root).is_dir(), "SYSTEM_ROOT_REQUIRED")
        path_parts.append(str(Path(system_root) / "System32"))
    return {**kept, "PATH": os.pathsep.join(path_parts), "JAVA_HOME": str(java.parent.parent),
            "TEMP": str(run / "tmp"), "TMP": str(run / "tmp"), "TMPDIR": str(run / "tmp"),
            "USERPROFILE": str(run / "home"), "APPDATA": str(run / "appdata"), "LOCALAPPDATA": str(run / "localappdata")}


def close_stdin_eof(process):
    need(process.stdin is not None and not process.stdin.closed, "EOF_PIPE_REQUIRED")
    process.stdin.close()
    need(process.stdin.closed, "EOF_PIPE_CLOSE_UNCONFIRMED")


def check_execution_inputs(plan):
    run = Path(plan["paths"]["evidence_dir"]) / "run"
    tree_files(run, maximum=1000)  # Includes home/config and catches startup SQL or links.
    need(read_regular(run / "validate.sql") == validation_script(run / "apexlang"), "VALIDATION_SCRIPT_CHANGED")
    files = tree_files(run / "apexlang")
    expected = plan["input"]["file_sha256"]
    need(set(files) == set(expected) and all(sha(read_regular(path, MAX_INPUT_BYTES)) == expected[name]
                                           for name, path in files.items()), "VALIDATION_SNAPSHOT_CHANGED")


def child(plan, name, plan_sha):
    need(name in {"version", "validation"}, "FIXED_VALIDATION_STEP_REQUIRED")
    run = Path(plan["paths"]["evidence_dir"]) / "run"
    argv = plan["commands"][name]
    need(argv == command_argv(plan["paths"], plan["installation"], name), "FIXED_CHILD_ARGUMENTS_REQUIRED")
    seconds = plan["version_timeout_seconds" if name == "version" else "validation_timeout_seconds"]
    need(type(seconds) is int and 1 <= seconds <= MAX_TIMEOUT, "CHILD_TIMEOUT_BOUND_REQUIRED")
    check_execution_inputs(plan)
    environment = child_environment(plan["paths"])
    save_new(run / f"{name}-intent.json", {"scope": "fox-offline-validation-child-v1", "step": name,
        "argv": argv, "cwd": str(run), "plan_sha256": plan_sha, "timeout_seconds": seconds,
        "environment_names": sorted(environment), "stdin": {"mode": "EOF_PIPE", "bytes": 0},
        "started_at_utc": datetime.now(timezone.utc).isoformat()})
    out_path, err_path = run / f"{name}.stdout", run / f"{name}.stderr"
    process, reason = None, None
    with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(argv, cwd=run, env=environment, shell=False, stdin=subprocess.PIPE,
                stdout=stdout, stderr=stderr, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            close_stdin_eof(process)
            save_new(run / f"{name}-started.json", {"pid": process.pid, "plan_sha256": plan_sha,
                "stdin_eof_closed": True, "stdin_bytes": 0, "ownership": "original_Popen_process_handle"})
            deadline = time.monotonic() + seconds
            while process.poll() is None:
                if out_path.stat().st_size > MAX_STREAM or err_path.stat().st_size > MAX_STREAM:
                    reason = "OUTPUT_LIMIT"
                    break
                if time.monotonic() >= deadline:
                    reason = "TIMEOUT"
                    break
                time.sleep(0.2)
            if reason:
                process.kill()  # Original Popen handle; never a name/PID-wide kill.
            process.wait(timeout=10)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
                save_new(run / f"{name}-exception-cleanup.json", {"pid": process.pid,
                    "exit_code": process.returncode, "owned_Popen_handle_used": True,
                    "validation_success_claimed": False})
    need(process is not None and type(process.returncode) is int, "CHILD_EXIT_UNCONFIRMED")
    sizes = {"stdout": out_path.stat().st_size, "stderr": err_path.stat().st_size}
    result = {"step": name, "pid": process.pid, "exit_code": process.returncode, "stop_reason": reason,
              "plan_sha256": plan_sha, "exact_child_exit_observed": True,
              "ownership": "original_Popen_process_handle", "output_bytes": sizes}
    if all(size <= MAX_STREAM for size in sizes.values()):
        out, err = read_regular(out_path, MAX_STREAM), read_regular(err_path, MAX_STREAM)
        result.update(stdout_sha256=sha(out), stderr_sha256=sha(err))
        text = (out + b"\n" + err).decode("utf-8", errors="replace")
    else:
        text = ""
        result["stop_reason"] = reason or "OUTPUT_LIMIT"
    save_new(run / f"{name}-exit.json", result)
    need(result["stop_reason"] is None and not STOP_TEXT.search(text), "CHILD_LIMIT_OR_CONNECTION_UNCERTAINTY")
    return result, text


def successful_validation(exit_code, text):
    return (type(exit_code) is int and exit_code == 0 and type(text) is str
            and any(line.strip() == "Validation successful." for line in text.splitlines())
            and not ERROR_TEXT.search(text) and not STOP_TEXT.search(text))


def confirmed_version(exit_code, text):
    versions = re.findall(r"(?m)^SQLcl:\s+Release\s+(\S+)", text) if type(text) is str else []
    return (type(exit_code) is int and exit_code == 0 and versions == [SQLCL_VERSION]
            and not ERROR_TEXT.search(text) and not STOP_TEXT.search(text))


def validation_verdict(exit_code, text):
    if successful_validation(exit_code, text):
        return "VALID", "SQLCL_VALIDATION_SUCCEEDED"
    if (type(exit_code) is int and exit_code in (0, 1, 2) and type(text) is str
            and re.search(r"(?m)^\s*APEXLang Compile Errors\b", text)
            and not STOP_TEXT.search(text)
            and not re.search(r"\b(?:SEVERE|[A-Za-z0-9_.$]*(?:Exception|Error))\b", text, re.I)
            and not any(line.strip() == "Validation successful." for line in text.splitlines())):
        return "INVALID", "APEXLANG_COMPILER_REJECTED_INPUT"
    return "UNCONFIRMED", "SQLCL_DID_NOT_CONFIRM_A_VALIDATION_RESULT"


def verify_child_evidence(run_dir, name, receipt):
    raw = read_regular(run_dir / f"{name}-exit.json")
    need(raw == canonical(receipt) and
         sha(read_regular(run_dir / f"{name}.stdout", MAX_STREAM)) == receipt["stdout_sha256"] and
         sha(read_regular(run_dir / f"{name}.stderr", MAX_STREAM)) == receipt["stderr_sha256"],
         "CHILD_EVIDENCE_CHANGED")
    return sha(raw)


def run(plan_path, expected_sha):
    plan = load_plan(plan_path, expected_sha)
    evidence, snapshot = Path(plan["paths"]["evidence_dir"]), Path(plan["paths"]["evidence_dir"]) / "run/apexlang"
    run_dir = evidence / "run"
    need(not run_dir.exists(), "EXISTING_ATTEMPT_INSPECT_ONLY")
    need({path.name for path in evidence.iterdir()} == {"plan.json"}, "EVIDENCE_MEMBERS_CHANGED")
    _, contents = input_files(plan["paths"]["input_dir"], plan["paths"]["input_manifest"], plan["input"]["manifest_sha256"])
    run_dir.mkdir(mode=0o700)
    try:
        for name in ("home", "tmp", "prefs", "appdata", "localappdata", "apexlang"):
            (run_dir / name).mkdir(mode=0o700)
        for name, raw in contents.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            save_new(path, raw)
        save_new(run_dir / "validate.sql", validation_script(snapshot))
        need(load_plan(plan_path, expected_sha) == plan, "INPUT_CHANGED_BEFORE_EXECUTION")
        version, version_text = child(plan, "version", expected_sha)
        need(confirmed_version(version["exit_code"], version_text), "SQLCL_VERSION_UNCONFIRMED")
        need(load_plan(plan_path, expected_sha) == plan, "INPUT_CHANGED_AFTER_VERSION")
        validation, output = child(plan, "validation", expected_sha)
        need(load_plan(plan_path, expected_sha) == plan, "INPUT_CHANGED_AFTER_VALIDATION")
        snapshot_files = tree_files(snapshot)
        need(set(snapshot_files) == set(contents) and all(read_regular(path, MAX_INPUT_BYTES) == contents[name]
                                                        for name, path in snapshot_files.items()), "VALIDATION_SNAPSHOT_CHANGED")
        version_receipt = verify_child_evidence(run_dir, "version", version)
        validation_receipt = verify_child_evidence(run_dir, "validation", validation)
        status, code = validation_verdict(validation["exit_code"], output)
        passed = status == "VALID"
        result = {"schema_version": 1, "scope": "fox-offline-project-validation-result-v1",
            "status": status, "code": code, "passed": passed, "plan_sha256": expected_sha,
            "input_manifest_sha256": plan["input"]["manifest_sha256"], "sqlcl_version": SQLCL_VERSION,
            "version_exit_observed": version["exact_child_exit_observed"],
            "validation_exit_observed": validation["exact_child_exit_observed"],
            "validation_exit_code": validation["exit_code"], "inputs_unchanged": True,
            "version_exit_receipt_sha256": version_receipt, "validation_exit_receipt_sha256": validation_receipt,
            "validation_stdout_sha256": validation["stdout_sha256"], "validation_stderr_sha256": validation["stderr_sha256"],
            "snapshot_file_map_sha256": sha(canonical(plan["input"]["file_sha256"])),
            "snapshot_unchanged": True, "database_connection_supplied": False, "import_run": False,
            "runtime_verified": False, "human_acceptance_recorded": False,
            "automatic_replay_permitted": False,
            "next_action": ("Proceed to separately authorized import/runtime verification." if passed else
                            "Correct compiler-reported input issues and prepare a new bound attempt." if status == "INVALID" else
                            "Inspect tool/runtime diagnostics before changing source or preparing another attempt.")}
        save_new(run_dir / "result.json", result)
        return result
    except Exception as error:
        code = str(error) if isinstance(error, ValidationError) else "VALIDATION_OUTCOME_UNCONFIRMED"
        save_new(run_dir / "stopped.json", {"status": "STOPPED", "code": code,
            "plan_sha256": expected_sha, "automatic_replay_permitted": False})
        raise


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValidationError("ARGUMENTS_INVALID")


def main(argv=None):
    try:
        parser = SafeParser(description=__doc__)
        sub = parser.add_subparsers(dest="action", required=True)
        create = sub.add_parser("prepare")
        for name in ("sqlcl-home", "java", "input", "input-manifest", "manifest-sha256", "evidence-dir"):
            create.add_argument("--" + name, required=True)
        create.add_argument("--timeout-seconds", type=int, default=120)
        execute = sub.add_parser("run")
        execute.add_argument("--plan", required=True)
        execute.add_argument("--plan-sha256", required=True)
        args = parser.parse_args(argv)
        if args.action == "prepare":
            result = prepare(sqlcl_home=args.sqlcl_home, java=args.java, input_dir=args.input,
                input_manifest=args.input_manifest, manifest_sha256=args.manifest_sha256,
                evidence_dir=args.evidence_dir, timeout_seconds=args.timeout_seconds)
        else:
            result = run(args.plan, args.plan_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("passed", True) else (2 if result.get("status") == "INVALID" else 3)
    except Exception as error:
        code = str(error) if isinstance(error, ValidationError) else "VALIDATION_OUTCOME_UNCONFIRMED"
        print(json.dumps({"status": "STOPPED", "code": code, "automatic_replay_permitted": False}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
