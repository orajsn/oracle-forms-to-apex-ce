from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading

from .security import alias_for_job


_IMPORT_LOCK = threading.Lock()
_TARGET_DATABASE = 'ASZ8EQWFM8UNCA2_JSNF2APEX'


def _target_guard(workspace: str) -> str:
    # This deployment is restricted to the existing JSN ADB. Its DB_NAME was
    # correlated with the exact OCID using the protected administrative probe.
    return ("begin if sys_context('USERENV','DB_NAME') <> 'ASZ8EQWFM8UNCA2_JSNF2APEX' "
            f"or user <> '{workspace}' then raise_application_error(-20081,'FOX target identity mismatch'); end if; end;\n/")


def _sqlcl_input_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if '"' in value or "\n" in value or "\r" in value:
        raise ValueError("unsafe SQLcl input path")
    return value


def _run_script(sqlcl_path: Path, args: list[str], commands: list[str], cwd: Path, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    if not sqlcl_path.is_file():
        raise FileNotFoundError(f"SQLcl executable not found: {sqlcl_path}")
    fd, script_name = tempfile.mkstemp(prefix="f2a-sqlcl-", suffix=".sql", dir=cwd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("set echo off\nset heading off\nset feedback off\nset verify off\nwhenever sqlerror exit failure rollback\n")
            handle.write("\n".join(commands))
            handle.write("\nexit\n")
        return subprocess.run(
            [str(sqlcl_path), '-nohistory', *args, f"@{script_name}"],
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    finally:
        Path(script_name).unlink(missing_ok=True)


def validate_apexlang(sqlcl_path: Path, draft_path: Path, log_path: Path) -> dict:
    input_path = _sqlcl_input_path(draft_path)
    result = _run_script(sqlcl_path, ["-S", "/nolog"], [f'apex validate -input "{input_path}"'], draft_path.parent)
    output = result.stdout + ("\n" + result.stderr if result.stderr else "")
    log_path.write_text(output, encoding="utf-8")
    passed = (
        result.returncode == 0
        and "Validation successful" in output
        and "APEXLang Compile Errors" not in output
    )
    return {"passed": passed, "return_code": result.returncode, "log": str(log_path), "summary": output[-4000:]}


def _candidate_application_ids(job_id: str) -> list[int]:
    digest = hashlib.sha256(job_id.encode("utf-8")).digest()
    base = 100_000 + int.from_bytes(digest[:4], "big") % 800_000_000
    return [base + offset for offset in range(20)]


def import_apexlang(
    sqlcl_path: Path,
    connection_name: str,
    workspace: str,
    job_id: str,
    draft_path: Path,
    log_path: Path,
) -> dict:
    if not connection_name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", connection_name):
        raise RuntimeError("F2A_SQLCL_CONNECTION_NAME must name a saved SQLcl connection")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,29}", workspace):
        raise ValueError("unsafe APEX workspace name")
    alias = alias_for_job(job_id)
    input_path = _sqlcl_input_path(draft_path)

    with _IMPORT_LOCK:
        candidates = _candidate_application_ids(job_id)
        candidate_csv = ",".join(str(value) for value in candidates)
        precheck = _run_script(
            sqlcl_path,
            ["-S", "-L", "-name", connection_name],
            [
                _target_guard(workspace),
                "select 'F2A_ALIAS_COUNT=' || count(*) from apex_applications "
                f"where workspace = '{workspace}' and upper(alias) = '{alias}';",
                "select 'F2A_USED_ID=' || application_id from apex_applications "
                f"where application_id in ({candidate_csv});",
            ],
            draft_path.parent,
        )
        pre_output = precheck.stdout + "\n" + precheck.stderr
        if precheck.returncode != 0:
            raise RuntimeError(f"APEX pre-import check failed: {pre_output[-2000:]}")
        alias_match = re.search(r"F2A_ALIAS_COUNT=(\d+)", pre_output)
        if not alias_match or int(alias_match.group(1)) != 0:
            raise RuntimeError(f"application alias already exists or could not be proven absent: {alias}")
        used = {int(value) for value in re.findall(r"F2A_USED_ID=(\d+)", pre_output)}
        app_id = next((value for value in candidates if value not in used), None)
        if app_id is None:
            raise RuntimeError("no collision-free application ID candidate is available")

        result = _run_script(
            sqlcl_path,
            ["-S", "-L", "-name", connection_name],
            [
                _target_guard(workspace),
                f'apex import -input "{input_path}" -workspace {workspace} -id {app_id} '
                f'-alias {alias} -name "Forms2APEX {job_id}"'
            ],
            draft_path.parent,
            timeout=1200,
        )
        output = result.stdout + ("\n" + result.stderr if result.stderr else "")
        log_path.write_text(pre_output + "\n--- IMPORT ---\n" + output, encoding="utf-8")
        passed = result.returncode == 0 and "Import successful" in output
        if not passed:
            raise RuntimeError(f"APEX import failed: {output[-3000:]}")
        return {
            "application_id": app_id,
            "application_alias": alias,
            "workspace": workspace,
            "log": str(log_path),
        }


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _regular_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Import evidence file is missing or linked')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _input_members(path: Path) -> dict:
    if path.is_symlink():
        raise RuntimeError('Linked import input is not permitted')
    if path.is_file():
        if path.stat().st_size > 20_000_000:
            raise RuntimeError('Import input exceeds evidence limits')
        return {'kind': 'file', 'sha256': _regular_digest(path)}
    if not path.is_dir():
        raise RuntimeError('Import input directory is missing')
    members = {}
    total = 0
    for child in sorted(path.rglob('*')):
        if child.is_symlink():
            raise RuntimeError('Linked import input is not permitted')
        if child.is_dir():
            continue
        name = child.relative_to(path).as_posix()
        if not child.is_file() or '\\' in name or ':' in name or any(ord(c) < 32 for c in name):
            raise RuntimeError('Unsafe import evidence member')
        total += child.stat().st_size
        if len(members) >= 500 or total > 20_000_000:
            raise RuntimeError('Import input exceeds evidence limits')
        members[name] = _regular_digest(child)
    if not members:
        raise RuntimeError('Import input cannot be empty')
    # Same member-map digest convention as provenance.tree_digest.
    digest = hashlib.sha256(json.dumps(members, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {'kind': 'directory', 'sha256': digest, 'files': members}


def _immutable_record(path: Path, payload: dict) -> dict:
    """Exclusive + fsync before any DB mutation. A partial file blocks replay."""
    record = dict(payload)
    record['record_sha256'] = hashlib.sha256(_canonical_json(payload)).hexdigest()
    with path.open('xb') as handle:
        handle.write(_canonical_json(record))
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != 'nt':
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return record


def _read_immutable_record(path: Path) -> dict:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            raise ValueError('Missing or linked record')
        record = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(record, dict):
            raise ValueError('Object required')
        payload = {key: value for key, value in record.items() if key != 'record_sha256'}
        if record.get('record_sha256') != hashlib.sha256(_canonical_json(payload)).hexdigest():
            raise ValueError('Record digest mismatch')
        return record
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError('Import durability evidence is missing or changed; operator reconciliation required') from exc


def _durable_arguments(connection_name, workspace, job_id, artifact_binding, expected_draft_sha256):
    if not isinstance(connection_name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', connection_name):
        raise ValueError('A saved SQLcl connection is required')
    if not isinstance(workspace, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{1,29}', workspace):
        raise ValueError('Unsafe APEX workspace name')
    alias = alias_for_job(job_id)
    if (not isinstance(expected_draft_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', expected_draft_sha256)
            or not isinstance(artifact_binding, dict) or artifact_binding.get('job_id') != job_id
            or expected_draft_sha256 not in (artifact_binding.get('draft_sha256'), artifact_binding.get('draft_zip_sha256'))):
        raise ValueError('Import requires the exact validated draft/package binding')
    return alias


def _check_durability_paths(intent_path, draft_path, log_path):
    if not intent_path.parent.is_dir() or intent_path.parent.is_symlink():
        raise ValueError('Import durability records require an existing regular job directory')
    protected = {intent_path.resolve(), _receipt_path(intent_path).resolve()}
    if log_path.is_symlink() or log_path.resolve() in protected:
        raise ValueError('Import log must not overwrite durability evidence')
    draft = draft_path.resolve()
    if draft_path.is_dir() and (intent_path.resolve().is_relative_to(draft) or log_path.resolve().is_relative_to(draft)):
        raise ValueError('Import records and logs must be outside the frozen draft')


def _one_marker(output: str, marker: str, expected: str) -> bool:
    return re.findall(r'^\s*' + re.escape(marker) + r'=(\d+)\s*$', output, re.MULTILINE) == [expected]


def _capture_compiled_metadata(sqlcl_path, connection_name, workspace, app_id, alias, root):
    """Documented SQLcl APEXlang export captures all compiled components.

    No approximate catalog counts or normalization of omitted/default fields
    are treated as equivalence. Exact export mismatches require an operator.
    """
    capture = Path(tempfile.mkdtemp(prefix='.import-capture-', dir=root))
    identity = (f"workspace='{workspace}' and application_id={app_id} and upper(alias)='{alias}'")
    result = _run_script(sqlcl_path, ['-S', '-L', '-name', connection_name], [
        _target_guard(workspace),
        f"select 'F2A_CAPTURE_IDENTITY='||count(*) from apex_applications where {identity};",
        f"select 'F2A_CAPTURE_ALIAS='||count(*) from apex_applications where workspace='{workspace}' and upper(alias)='{alias}';",
        f'apex export -applicationid {app_id} -exptype APEXLANG',
        f"select 'F2A_CAPTURE_IDENTITY_AFTER='||count(*) from apex_applications where {identity};",
    ], capture)
    output = result.stdout + '\n' + result.stderr
    (capture / 'capture.log').write_text(output, encoding='utf-8')
    if result.returncode or not all(_one_marker(output, name, '1') for name in
            ('F2A_CAPTURE_IDENTITY', 'F2A_CAPTURE_ALIAS', 'F2A_CAPTURE_IDENTITY_AFTER')):
        raise RuntimeError('Exact imported application identity is not proven; no import replay is permitted')
    app = capture / alias.lower()
    if not (app / 'application.apx').is_file():
        raise RuntimeError('Compiled APEXlang export is incomplete')
    metadata = _input_members(app)
    validation = validate_apexlang(sqlcl_path, app, capture / 'validation.log')
    if not validation.get('passed') or _input_members(app) != metadata:
        raise RuntimeError('Compiled APEXlang export did not remain valid and unchanged')
    for path in app.rglob('*'):
        if path.is_file():
            with path.open('r+b') as handle:
                os.fsync(handle.fileno())
    if os.name != 'nt':
        directories = [app, *(p for p in app.rglob('*') if p.is_dir())]
        for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            descriptor = os.open(path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    return {'format': 'APEXLANG', 'scope': 'complete_compiled_export_exact_bytes',
            'snapshot_directory': app.relative_to(root).as_posix(), 'validated': True, **metadata}


def _receipt_path(intent_path: Path) -> Path:
    return intent_path.with_name(intent_path.stem + '-receipt.json')


def import_apexlang_durable(
    sqlcl_path: Path, connection_name: str, workspace: str, job_id: str,
    draft_path: Path, log_path: Path, *, intent_path: Path,
    expected_draft_sha256: str, artifact_binding: dict,
    pre_write_check=None,
) -> dict:
    """One import attempt with immutable reservation and compiled-output proof.

    An existing intent is *always* refused, including a completed attempt. Use
    reconcile_apexlang_import only to recover a previously verified success.
    A timeout before a complete receipt remains deliberately fail-closed.
    """
    alias = _durable_arguments(connection_name, workspace, job_id, artifact_binding, expected_draft_sha256)
    if pre_write_check is not None and not callable(pre_write_check):
        raise ValueError('A callable pre-write freshness check is required')
    input_path = _sqlcl_input_path(draft_path)
    intent_path = Path(intent_path)
    _check_durability_paths(intent_path, draft_path, log_path)
    with _IMPORT_LOCK:
        if intent_path.exists() or intent_path.is_symlink() or _receipt_path(intent_path).exists():
            raise RuntimeError('An import reservation already exists; automatic replay is blocked')
        input_metadata = _input_members(draft_path)
        if input_metadata['sha256'] != expected_draft_sha256:
            raise RuntimeError('Import input differs from the validated artifact')
        candidates = _candidate_application_ids(job_id)
        precheck = _run_script(sqlcl_path, ['-S', '-L', '-name', connection_name], [
            _target_guard(workspace),
            f"select 'F2A_ALIAS_COUNT='||count(*) from apex_applications where workspace='{workspace}' and upper(alias)='{alias}';",
            "select 'F2A_USED_ID='||application_id from apex_applications where application_id in (" + ','.join(map(str, candidates)) + ');',
        ], draft_path.parent)
        pre_output = precheck.stdout + '\n' + precheck.stderr
        if precheck.returncode or not _one_marker(pre_output, 'F2A_ALIAS_COUNT', '0'):
            raise RuntimeError('Import alias is not proven absent; existing applications are preserved')
        used = {int(value) for value in re.findall(r'^\s*F2A_USED_ID=(\d+)\s*$', pre_output, re.MULTILINE)}
        app_id = next((value for value in candidates if value not in used), None)
        if app_id is None:
            raise RuntimeError('No collision-free application ID candidate is available')
        if _input_members(draft_path) != input_metadata:
            raise RuntimeError('Import input changed during reservation checks')
        if pre_write_check is not None:pre_write_check()
        intent = _immutable_record(intent_path, {
            'schema_version': 1, 'kind': 'sqlcl-apexlang-import-reservation',
            'job_id': job_id, 'target_database': _TARGET_DATABASE,
            'connection_name': connection_name, 'workspace': workspace,
            'application_id': app_id, 'application_alias': alias,
            'artifact_binding': artifact_binding, 'input': input_metadata,
        })
        if pre_write_check is not None:pre_write_check()
        result = _run_script(sqlcl_path, ['-S', '-L', '-name', connection_name], [
            _target_guard(workspace),
            "declare n number; begin select count(*) into n from apex_applications "
            f"where application_id={app_id} or (workspace='{workspace}' and upper(alias)='{alias}'); "
            "if n<>0 then raise_application_error(-20082,'FOX reserved application already exists'); end if; end;\n/",
            f'apex import -input "{input_path}" -workspace {workspace} -id {app_id} '
            f'-alias {alias} -name "Forms2APEX {job_id}"',
        ], draft_path.parent, timeout=1200)
        output = result.stdout + '\n' + result.stderr
        log_path.write_text(pre_output + '\n--- IMPORT ---\n' + output, encoding='utf-8')
        if result.returncode or 'Import successful' not in output:
            raise RuntimeError('APEX import was not confirmed; reserved application requires reconciliation')
        if _input_members(draft_path) != input_metadata:
            raise RuntimeError('Import input changed during execution; reserved application requires reconciliation')
        compiled = _capture_compiled_metadata(sqlcl_path, connection_name, workspace, app_id, alias, intent_path.parent)
        if _input_members(draft_path) != input_metadata or _read_immutable_record(intent_path) != intent:
            raise RuntimeError('Import evidence changed before confirmation; reconciliation required')
        _immutable_record(_receipt_path(intent_path), {
            'schema_version': 1, 'kind': 'sqlcl-apexlang-import-confirmation',
            'intent_sha256': intent['record_sha256'], 'sqlcl_import_confirmed': True,
            'compiled_metadata': compiled,
        })
        return {'application_id': app_id, 'application_alias': alias, 'workspace': workspace,
            'log': str(log_path), 'import_intent_sha256': intent['record_sha256'],
            'compiled_metadata_sha256': compiled['sha256'], 'reconciled': False}


def reconcile_apexlang_import(
    sqlcl_path: Path, connection_name: str, workspace: str, job_id: str,
    draft_path: Path, log_path: Path, *, intent_path: Path,
    expected_draft_sha256: str, artifact_binding: dict,
) -> dict:
    """Read-only target reconciliation; never performs an import or updates state.

    Only a confirmed import's durable full compiled-export receipt permits
    recovery. Identity alone, approximate counts, logs, or guessed mappings do
    not prove that an interrupted first import completed correctly.
    """
    alias = _durable_arguments(connection_name, workspace, job_id, artifact_binding, expected_draft_sha256)
    intent_path = Path(intent_path)
    _check_durability_paths(intent_path, draft_path, log_path)
    with _IMPORT_LOCK:
        intent = _read_immutable_record(intent_path)
        if (intent.get('schema_version') != 1 or intent.get('kind') != 'sqlcl-apexlang-import-reservation'
                or intent.get('job_id') != job_id or intent.get('workspace') != workspace
                or intent.get('connection_name') != connection_name or intent.get('application_alias') != alias
                or intent.get('target_database') != _TARGET_DATABASE or intent.get('artifact_binding') != artifact_binding
                or type(intent.get('application_id')) is not int or intent['application_id'] <= 0
                or intent.get('input') != _input_members(draft_path)
                or intent['input']['sha256'] != expected_draft_sha256):
            raise RuntimeError('Import reservation does not match the current validated artifact and target')
        receipt = _read_immutable_record(_receipt_path(intent_path))
        if (receipt.get('schema_version') != 1 or receipt.get('kind') != 'sqlcl-apexlang-import-confirmation'
                or receipt.get('intent_sha256') != intent['record_sha256']
                or receipt.get('sqlcl_import_confirmed') is not True):
            raise RuntimeError('No exact compiled import completion proof is available; operator reconciliation required')
        compiled = receipt.get('compiled_metadata', {})
        if not isinstance(compiled, dict):
            raise RuntimeError('Compiled import completion proof is invalid')
        snapshot = compiled.get('snapshot_directory', '')
        if (not isinstance(snapshot, str)
                or not re.fullmatch(r'\.import-capture-[A-Za-z0-9_-]+/' + re.escape(alias.lower()), snapshot)
                or compiled.get('format') != 'APEXLANG' or compiled.get('validated') is not True
                or compiled.get('scope') != 'complete_compiled_export_exact_bytes'):
            raise RuntimeError('Compiled import completion proof is invalid')
        expected = {key: compiled[key] for key in ('kind', 'sha256', 'files') if key in compiled}
        if (intent_path.parent / snapshot).parent.is_symlink() or _input_members(intent_path.parent / snapshot) != expected:
            raise RuntimeError('Recorded compiled metadata changed; operator reconciliation required')
        current = _capture_compiled_metadata(sqlcl_path, connection_name, workspace, intent['application_id'], alias, intent_path.parent)
        if {key: current[key] for key in ('kind', 'sha256', 'files')} != expected:
            raise RuntimeError('Live compiled application differs from confirmed metadata; no automatic recovery')
        if (_read_immutable_record(intent_path) != intent or _read_immutable_record(_receipt_path(intent_path)) != receipt
                or _input_members(draft_path) != intent['input']):
            raise RuntimeError('Import evidence changed during reconciliation')
        proof = {'application_id': intent['application_id'], 'application_alias': alias, 'workspace': workspace,
            'log': str(log_path), 'import_intent_sha256': intent['record_sha256'],
            'compiled_metadata_sha256': current['sha256'], 'reconciled': True,
            'reconciliation_scope': 'exact_identity_and_complete_compiled_metadata', 'target_writes': False}
        log_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding='utf-8')
        return proof
