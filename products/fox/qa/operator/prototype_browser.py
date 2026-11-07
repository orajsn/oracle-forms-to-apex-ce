"""Host-side new-profile browser callback. Inert on import; no secret reads.

Use only through the existing authorized host/SSH executor. The converter is
NOT assumed to contain Podman. A trusted credential_authorizer must establish
the existing original-workspace credential provenance; clean-allocation QA
credentials are not adopted. No image build/pull, install, ports or SQL occurs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from forms2apex import native_blueprint
from forms2apex.project_reviews import canonical, digest, read_object
from forms2apex.prototype_release import expected_runtime_pages, runtime_binding, validate_runtime_receipt
from forms2apex.provenance import file_digest
from .native_qa_remote import command as host_command


ORIGIN = "https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com"
DB_NAME = "ASZ8EQWFM8UNCA2_JSNF2APEX"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_ROOT = Path(__file__).resolve().parents[1]
OBSERVATION_MARGIN_SECONDS = 15
ROOTLESS_V1_WARNING = b'Resource limits are not supported and ignored on cgroups V1 rootless systems'


def launch_diagnostics_allowed(stderr):
    # Podman still enforces conmon's timeout on this host. CPU/memory/pids flags
    # are best-effort on rootless cgroups v1, NOT an enforced resource sandbox.
    return all(line.strip() == ROOTLESS_V1_WARNING for line in stderr.splitlines() if line.strip())


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def private(path, *, directory=False, secret=False):
    """Metadata only for credential files; never open/read their contents."""
    path = Path(path)
    need(os.name == "posix" and path.is_absolute() and ".." not in path.parts,
         "PROTOTYPE_BROWSER_POSIX_PRIVATE_HOST_REQUIRED")
    need(all(ord(char) >= 32 and char != ":" for char in str(path)), "PROTOTYPE_BROWSER_UNSAFE_MOUNT_PATH")
    for parent in (*reversed(path.parents), path):
        need(not parent.is_symlink(), "PROTOTYPE_BROWSER_LINKED_PATH")
    value = path.stat()
    need(value.st_uid == os.getuid() and value.st_nlink == (1 if not directory else value.st_nlink)
         and stat.S_IMODE(value.st_mode) in ({0o700} if directory else {0o400, 0o600})
         and (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)),
         "PROTOTYPE_BROWSER_PRIVATE_OWNER_MODE_REQUIRED")
    if secret:
        need(0 < value.st_size <= 8192, "PROTOTYPE_BROWSER_CREDENTIAL_SIZE_INVALID")
    return path


def new(path, raw):
    with Path(path).open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600) if os.name == "posix" else None
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


@dataclass(frozen=True)
class PrototypeBrowserConfig:
    jobs_root: Path
    qa_root: Path
    image_id: str
    credentials_file: Path
    owner_uid: int
    owner_gid: int
    request_deadline_at_utc: str | None = None
    execution_deadline_at_utc: str | None = None


def browser_deadline(config):
    """Fail closed on absent expiry; leave time to observe daemon termination."""
    values = (config.request_deadline_at_utc,
              config.execution_deadline_at_utc or config.request_deadline_at_utc)
    try:
        need(all(type(value) is str and len(value) <= 40 for value in values),
             "PROTOTYPE_BROWSER_ABSOLUTE_DEADLINE_REQUIRED")
        deadlines = [datetime.fromisoformat(value) for value in values]
        need(all(value.tzinfo is not None and value.utcoffset().total_seconds() == 0 for value in deadlines),
             "PROTOTYPE_BROWSER_ABSOLUTE_DEADLINE_REQUIRED")
    except (ValueError, TypeError):
        raise RuntimeError("PROTOTYPE_BROWSER_ABSOLUTE_DEADLINE_REQUIRED") from None
    now = datetime.now(timezone.utc)
    need(all((value - now).total_seconds() <= 540 for value in deadlines),
         "PROTOTYPE_BROWSER_DEADLINE_TOO_LONG")
    deadline = min(deadlines) - timedelta(seconds=OBSERVATION_MARGIN_SECONDS)
    need((deadline - now).total_seconds() >= 1, "PROTOTYPE_BROWSER_EXPIRED_UNKNOWN_NO_REPLAY")
    return deadline


class PrototypeBrowser:
    """runtime_verifier callback on the existing rootless operator host.

    credential_authorizer(request, credential_file=Path) returns exactly:
      schema_version=1, scope=fox-prototype-runtime-credentials-target-v1,
      workspace=FORMS2APEX_POC, db_name=DB_NAME, ords_origin=ORIGIN,
      credentials_sha256, username_sha256, authorization_reference_sha256.
    That trusted hook rereads existing account authorization/target provenance;
    these hashes or a user-supplied approval boolean alone are not authority.
    Python never opens credentials; only the isolated browser reads the exact
    protected read-only mount and checks its bytes and observed APP_USER hash.

    command(args, timeout=..., allowed=(...)) defaults to the existing host
    command implementation. Remote providers must invoke this callback ON the
    bound existing host through their current SSH transport, not expose Podman
    or add a public service. No command is executed during construction.
    """

    def __init__(self, config=None, *, command=None, credential_authorizer=None):
        self.config = config
        self.command = command or host_command
        self.credential_authorizer = credential_authorizer

    def __call__(self, request, *, root, imported, trace, artifact_binding, freshness_check):
        config = self.config
        need(isinstance(config, PrototypeBrowserConfig) and callable(self.credential_authorizer),
             "PROTOTYPE_BROWSER_CONFIGURATION_UNAVAILABLE")
        need(type(config.owner_uid) is int and config.owner_uid > 0 and type(config.owner_gid) is int
             and config.owner_gid >= 0 and getattr(os, "getuid", lambda: -1)() == config.owner_uid
             and getattr(os, "getgid", lambda: -1)() == config.owner_gid,
             "PROTOTYPE_BROWSER_ROOTLESS_OWNER_REQUIRED")
        need(type(config.image_id) is str and _IMAGE.fullmatch(config.image_id),
             "PROTOTYPE_BROWSER_IMMUTABLE_IMAGE_REQUIRED")
        deadline = browser_deadline(config)
        def fresh():
            freshness_check()
            need(datetime.now(timezone.utc) < deadline, "PROTOTYPE_BROWSER_EXPIRED_UNKNOWN_NO_REPLAY")
        fresh()
        spec = native_blueprint.validate_prototype_spec(request["rendering_spec"])
        need(trace == native_blueprint.prototype_trace(spec), "PROTOTYPE_BROWSER_TRACE_CHANGED")
        root, jobs = Path(root), Path(config.jobs_root)
        private(jobs, directory=True)
        private(root, directory=True)
        need(root == jobs / request["job_id"] / "prototype-converter", "PROTOTYPE_BROWSER_EXACT_JOB_REQUIRED")
        private(config.qa_root, directory=True)
        private(config.credentials_file, secret=True)
        authority = self.credential_authorizer(request, credential_file=Path(config.credentials_file))
        expected = {"schema_version": 1, "scope": "fox-prototype-runtime-credentials-target-v1",
                    "workspace": "FORMS2APEX_POC", "db_name": DB_NAME, "ords_origin": ORIGIN}
        hashes = {"credentials_sha256", "username_sha256", "authorization_reference_sha256"}
        need(type(authority) is dict and set(authority) == set(expected) | hashes
             and type(authority["schema_version"]) is int
             and all(authority.get(key) == value for key, value in expected.items())
             and all(type(authority[key]) is str and _SHA.fullmatch(authority[key]) for key in hashes),
             "PROTOTYPE_BROWSER_ORIGINAL_WORKSPACE_CREDENTIAL_AUTHORITY_REQUIRED")
        # Do not start any browser if a form cannot retain a labelled synthetic
        # marker or if a required field has no reviewed input policy.
        for block in spec["blocks"]:
            if block["native_component"] == "form":
                need(any(field["data_type"] == "VARCHAR2" and field["in_edit_form"] and field["length"] >= 16
                         for field in block["fields"])
                     and all(field["nullable"] or field["in_edit_form"] for field in block["fields"]),
                     "PROTOTYPE_BROWSER_LABELLED_FORM_INPUT_POLICY_UNAVAILABLE")
        scripts = {"run-prototype.mjs": _ROOT / "run-prototype.mjs", "lib/contracts.mjs": _ROOT / "lib/contracts.mjs"}
        code = {name: file_digest(path) for name, path in scripts.items()}
        identity = runtime_binding(request, imported, artifact_binding)
        packet = {"binding": identity, "spec": spec, "trace": trace, "pages": expected_runtime_pages(spec),
                  "credential_authority": authority, "runner_files": code, "code_sha256": digest(code),
                  "image_id": config.image_id, "data_retention": "synthetic_test_rows_retained",
                  "deadline_at_utc": deadline.isoformat(), "request_deadline_at_utc": config.request_deadline_at_utc,
                  "url": ORIGIN + "/ords/r/forms2apex_poc/" + imported["application_alias"].lower() + "/"}
        fresh()
        info = self.command(["podman", "--remote=false", "info", "--format", "{{.Host.Security.Rootless}}"])
        need(info.stdout.strip() == b"true", "PROTOTYPE_BROWSER_ROOTLESS_ENGINE_REQUIRED")
        image = self.command(["podman", "--remote=false", "image", "inspect", config.image_id, "--format", "{{.Id}}"])
        # Podman versions return either bare hex or sha256:hex for .Id. Strip
        # only that optional prefix; never accept shortened/different digests.
        observed = image.stdout.strip()
        if observed.startswith(b"sha256:"):
            observed = observed[len(b"sha256:"):]
        need(re.fullmatch(rb"[a-f0-9]{64}", observed) is not None
             and b"sha256:" + observed == config.image_id.encode("ascii"),
             "PROTOTYPE_BROWSER_MEASURED_IMAGE_CHANGED")
        attempt = Path(config.qa_root) / ("prototype-" + digest(identity))
        need(not attempt.exists() and not attempt.is_symlink(), "PROTOTYPE_BROWSER_ATTEMPT_ALREADY_EXISTS_NO_REPLAY")
        attempt.mkdir(mode=0o700)
        source = attempt / "source"
        source.mkdir(mode=0o700)
        for name, path in scripts.items():
            copied = source / name
            copied.parent.mkdir(mode=0o700, exist_ok=True)
            new(copied, path.read_bytes())
        target = attempt / "target.json"
        new(target, canonical(packet))
        results = root / "runtime-evidence"
        need(not results.exists() and not results.is_symlink(), "PROTOTYPE_BROWSER_EVIDENCE_ALREADY_EXISTS")
        results.mkdir(mode=0o700)
        args = ["podman", "--remote=false", "run", "--rm", "--init", "--pull=never", "--userns=keep-id",
                "--user", f"{config.owner_uid}:{config.owner_gid}", "--read-only", "--cap-drop=all",
                "--security-opt=no-new-privileges", "--ipc=private", "--shm-size=256m", "--cpus=1",
                "--memory=1536m", "--pids-limit=256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777"]
        # Dedicated credential file only, never wallet/.ssh/config directories.
        for source, destination, mode in ((target, "/inputs/target.json", "ro"),
                (config.credentials_file, "/inputs/credentials.json", "ro"),
                (source / "run-prototype.mjs", "/opt/fox-qa/run-prototype.mjs", "ro"),
                (source / "lib/contracts.mjs", "/opt/fox-qa/lib/contracts.mjs", "ro"),
                (results, "/results", "rw"), (attempt, "/dispatch", "rw")):
            # Never relabel the retained credential file. Its existing operator
            # SELinux context must already permit the approved read-only mount.
            suffix = mode if Path(source) == Path(config.credentials_file) else mode + ",Z"
            args += ["--volume", f"{Path(source).as_posix()}:{destination}:{suffix}"]
        fresh()
        # Create-only durable dispatch before any possible browser write.
        new(attempt / "launch-intent.json", canonical({"binding": identity, "code_sha256": digest(code),
             "image_id": config.image_id, "state": "ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY",
             "deadline_at_utc": packet["deadline_at_utc"], "request_deadline_at_utc": config.request_deadline_at_utc}))
        fresh()
        # Derive the daemon lifetime AFTER the final potentially blocking
        # authority call and intent fsync, not before either consumes budget.
        lifetime = int((deadline - datetime.now(timezone.utc)).total_seconds())
        need(lifetime >= 1, "PROTOTYPE_BROWSER_EXPIRED_UNKNOWN_NO_REPLAY")
        args += ["--timeout", str(lifetime), "--stop-timeout", "1",
                 "--entrypoint", "node", config.image_id, "/opt/fox-qa/run-prototype.mjs"]
        # This bounds the actual container via Podman's daemon/conmon, not just
        # the client. A client timeout remains UNKNOWN: it is never evidence
        # that the container ended or that an in-flight write did not commit.
        completed = self.command(args, timeout=lifetime + OBSERVATION_MARGIN_SECONDS, allowed=(0,))
        need(completed.returncode == 0 and launch_diagnostics_allowed(completed.stderr) and len(completed.stdout) <= 8192,
             "PROTOTYPE_BROWSER_EXECUTION_NOT_CONFIRMED")
        need(json.loads(completed.stdout) == {"status": "PASSED", "business_behavior_accepted": False},
             "PROTOTYPE_BROWSER_EXECUTION_NOT_CONFIRMED")
        need({name: file_digest(path) for name, path in scripts.items()} == code,
             "PROTOTYPE_BROWSER_EXECUTED_SOURCE_CHANGED")
        fresh()
        report_path = results / "browser-report.json"
        private(report_path)
        report = read_object(report_path)
        need(report.get("runner") == {"kind": "authenticated_browser", "tool": "playwright",
             "code_sha256": digest(code), "image_id": config.image_id}, "PROTOTYPE_BROWSER_EXECUTOR_CHANGED")
        receipt = {**report, "artifacts": [{"path": "runtime-evidence/browser-report.json",
                    "sha256": file_digest(report_path), "bytes": report_path.stat().st_size}]}
        validate_runtime_receipt(root, request, imported, artifact_binding, receipt)
        return receipt

    def recover(self, request, *, root, imported, trace, artifact_binding):
        """Read completed private browser bytes only; no commands or retries."""
        config = self.config
        need(isinstance(config, PrototypeBrowserConfig), "PROTOTYPE_BROWSER_CONFIGURATION_UNAVAILABLE")
        root = Path(root)
        need(root == Path(config.jobs_root) / request["job_id"] / "prototype-converter",
             "PROTOTYPE_BROWSER_EXACT_JOB_REQUIRED")
        identity = runtime_binding(request, imported, artifact_binding)
        attempt = Path(config.qa_root) / ("prototype-" + digest(identity))
        if not attempt.exists() and not attempt.is_symlink():
            return None
        private(attempt, directory=True)
        packet = read_object(attempt / "target.json")
        need(packet.get("binding") == identity and packet.get("trace") == trace
             and packet.get("spec") == request["rendering_spec"] and packet.get("image_id") == config.image_id,
             "PROTOTYPE_BROWSER_RETAINED_BINDING_CHANGED")
        files = {name: file_digest(attempt / "source" / name) for name in ("run-prototype.mjs", "lib/contracts.mjs")}
        need(packet.get("runner_files") == files and packet.get("code_sha256") == digest(files),
             "PROTOTYPE_BROWSER_RETAINED_SOURCE_CHANGED")
        intent = read_object(attempt / "launch-intent.json")
        need(intent == {"binding": identity, "code_sha256": digest(files),
             "image_id": config.image_id, "state": "ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY",
             "deadline_at_utc": packet.get("deadline_at_utc"),
             "request_deadline_at_utc": packet.get("request_deadline_at_utc")},
             "PROTOTYPE_BROWSER_RETAINED_DISPATCH_CHANGED")
        path = root / "runtime-evidence/browser-report.json"
        if not path.exists() and not path.is_symlink():
            return None
        private(path)
        report = read_object(path)
        receipt = {**report, "artifacts": [{"path": "runtime-evidence/browser-report.json", "sha256": file_digest(path),
                                            "bytes": path.stat().st_size}]}
        need(report.get("runner") == {"kind": "authenticated_browser", "tool": "playwright",
             "code_sha256": digest(files), "image_id": config.image_id}, "PROTOTYPE_BROWSER_EXECUTOR_CHANGED")
        validate_runtime_receipt(root, request, imported, artifact_binding, receipt)
        return receipt
