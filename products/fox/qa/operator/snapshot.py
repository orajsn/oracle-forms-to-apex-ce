"""Stopped, explicit-role snapshots and isolated restore tests; standard library.

This module does not establish OCI scope, idle services or operator ownership.
The caller must hold those guards for the entire operation and pin the returned
completion digest in its own protected lifecycle receipt. Internal hashes prove
integrity, not authenticity against replacement of an entire private backup.
The caller must also reject restore destinations overlapping ANY live role root;
restore_test knows only its trusted backup and new isolated destination. Output
parents must already be owner-private and exclusively controlled by the caller.

The actual writer is POSIX-only. No original SQLite database is opened: DB and
sidecars are first captured byte-for-byte, then SQLite operates on private copies.
No service, network, secret lookup, deletion or restore over live data is provided.

Promoted from the retained 19 October snapshot engine. ``operator-state`` is an
additional directory role: its complete clean/project/journal/handoff tree is
captured without filtering hidden files. Protected files are assembled by the
caller in an explicit private directory; this module never discovers secrets.
The hosted wrapper must require its full four-role contract; legacy snapshots
with fewer roles remain readable under this generic integrity-only engine.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import tarfile
import time

ROLES = frozenset(("fox-data", "converter-jobs", "protected-config", "operator-state"))
SQLITE_MEMBERS = frozenset(("fox.sqlite3", "fox.sqlite3-wal", "fox.sqlite3-shm", "fox.sqlite3-journal"))
MAX_ENTRIES = 10000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + MAX_ENTRIES * 4096
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_ROWS = 200000
MAX_ROW_BYTES = 2 * 1024 * 1024
MAX_SQLITE_SECONDS = 30
SHA = re.compile(r"[a-f0-9]{64}\Z")
ENTRY_FIELDS = frozenset(("kind", "mode", "uid", "gid", "mtime_ns", "device", "inode"))
FILE_FIELDS = ENTRY_FIELDS | frozenset(("bytes", "sha256"))


class SnapshotError(ValueError):
    """Fixed public error code; never includes filenames, rows or exception text."""


def _need(value, code):
    if not value:
        raise SnapshotError(code)


def _raw(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _privacy(path=None, directory=False):
    """The single platform/privacy seam; real execution requires POSIX ownership."""
    _need(os.name == "posix", "POSIX_HOST_REQUIRED")
    if path is None:
        return
    info = path.lstat()
    _need(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
          and (stat.S_ISDIR(info.st_mode) if directory else
               stat.S_ISREG(info.st_mode) and info.st_nlink == 1), "PRIVATE_OWNER_STORAGE_REQUIRED")


def _path(value, must_exist=True):
    _need(isinstance(value, Path), "PATH_OBJECT_REQUIRED")
    path = Path(os.path.abspath(str(value)))
    for item in reversed((path,) + tuple(path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        _need(not stat.S_ISLNK(info.st_mode)
              and not getattr(info, "st_file_attributes", 0) & 0x400, "LINKED_PATH_PROHIBITED")
        _need(stat.S_ISDIR(info.st_mode) or
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "SPECIAL_OR_HARDLINK_PATH_PROHIBITED")
    _need(not must_exist or path.exists(), "PATH_NOT_FOUND")
    return path


def _disjoint(paths):
    for index, first in enumerate(paths):
        for second in paths[index + 1:]:
            try:
                overlap = os.path.commonpath((str(first), str(second))) in (str(first), str(second))
            except ValueError:
                overlap = False
            _need(not overlap, "PATHS_OVERLAP")


def _new_directory(path):
    _need(not os.path.lexists(str(path)) and path.parent.is_dir(), "CREATE_ONLY_DIRECTORY_REQUIRED")
    _path(path, False)
    _privacy(path.parent, True)
    os.mkdir(str(path), 0o700)
    os.chmod(str(path), 0o700)
    _privacy(path, True)


def _new_file(path, raw):
    _need(type(raw) is bytes, "FILE_BYTES_REQUIRED")
    _path(path, False)
    _privacy(path.parent, True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(str(path), flags, 0o600), "wb") as stream:
        if hasattr(os, "fchmod"):
            os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(str(path), 0o600)
    _privacy(path)


def _read(path, maximum=MAX_MEMBER_BYTES):
    path = _path(path)
    before = path.lstat()
    _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
          and 0 <= before.st_size <= maximum, "BOUNDED_REGULAR_FILE_REQUIRED")
    with os.fdopen(os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        opened = os.fstat(stream.fileno())
        _need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
              and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "FILE_CHANGED_DURING_OPEN")
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    _need(len(value) == before.st_size and len(value) <= maximum
          and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode,
               after.st_uid, after.st_gid, after.st_nlink)
          == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode,
              before.st_uid, before.st_gid, before.st_nlink), "FILE_CHANGED_DURING_READ")
    return value


def _entry(path):
    info = path.lstat()
    _need(not stat.S_ISLNK(info.st_mode)
          and not getattr(info, "st_file_attributes", 0) & 0x400, "LINKED_MEMBER_PROHIBITED")
    value = {"kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
             "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
             "mtime_ns": info.st_mtime_ns, "device": info.st_dev, "inode": info.st_ino}
    if value["kind"] == "file":
        raw = _read(path)
        value.update(bytes=len(raw), sha256=_sha(raw))
    return value


def _inventory(roles):
    values, total = {}, 0
    for role, root in sorted(roles.items()):
        _need(root.is_dir(), "ROLE_DIRECTORY_REQUIRED")
        pending = [(root, role)]
        while pending:
            path, name = pending.pop()
            _need(len(values) < MAX_ENTRIES and name not in values, "INVENTORY_LIMIT_OR_DUPLICATE")
            value = _entry(path)
            values[name] = value
            if value["kind"] == "directory":
                for child in sorted(path.iterdir(), reverse=True):
                    _need(child.name not in (".", "..") and "/" not in child.name
                          and "\\" not in child.name and ":" not in child.name, "MEMBER_NAME_INVALID")
                    pending.append((child, name + "/" + child.name))
            else:
                total += value["bytes"]
                _need(total <= MAX_TOTAL_BYTES, "TOTAL_BYTES_LIMIT")
    return values


def _stable(before, after):
    if set(before) != set(after):
        return False
    for name, original in before.items():
        current = after[name]
        if name == "fox-data/fox.sqlite3-shm":
            if original.get("kind") != "file" or current.get("kind") != "file":
                return False
            if {k: v for k, v in original.items() if k != "mtime_ns"} != {
                    k: v for k, v in current.items() if k != "mtime_ns"}:
                return False
        elif original != current:
            return False
    return True


def _member_path(name):
    _need(type(name) is str and 0 < len(name) <= 240 and "\\" not in name and ":" not in name
          and not any(ord(char) < 32 for char in name), "ARCHIVE_MEMBER_NAME_INVALID")
    path = PurePosixPath(name)
    _need(not path.is_absolute() and str(path) == name and ".." not in path.parts
          and path.parts and path.parts[0] in ROLES, "ARCHIVE_MEMBER_NAME_INVALID")
    return path


def _validate_inventory(value, roles):
    _need(type(value) is dict and 0 < len(value) <= MAX_ENTRIES, "INVENTORY_INVALID")
    total = 0
    for name, entry in value.items():
        parts = _member_path(name)
        _need(parts.parts[0] in roles and type(entry) is dict
              and entry.get("kind") in ("file", "directory"), "INVENTORY_INVALID")
        _need(set(entry) == (FILE_FIELDS if entry["kind"] == "file" else ENTRY_FIELDS), "INVENTORY_FIELDS_INVALID")
        for field in ENTRY_FIELDS - {"kind"}:
            _need(type(entry[field]) is int and entry[field] >= 0, "INVENTORY_METADATA_INVALID")
        _need(entry["mode"] <= 0o7777, "INVENTORY_MODE_INVALID")
        if entry["kind"] == "file":
            _need(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_MEMBER_BYTES
                  and type(entry["sha256"]) is str and SHA.fullmatch(entry["sha256"]), "INVENTORY_FILE_INVALID")
            total += entry["bytes"]
        if len(parts.parts) > 1:
            _need(value.get(str(parts.parent), {}).get("kind") == "directory", "INVENTORY_PARENT_MISSING")
    _need(total <= MAX_TOTAL_BYTES
          and all(value.get(role, {}).get("kind") == "directory" for role in roles), "INVENTORY_ROOT_OR_SIZE_INVALID")
    return total


def _write_archive(roles, inventory, path):
    _privacy(path.parent, True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(str(path), flags, 0o600), "wb") as output:
        if hasattr(os, "fchmod"):
            os.fchmod(output.fileno(), 0o600)
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, entry in sorted(inventory.items()):
                parts = _member_path(name)
                source = roles[parts.parts[0]].joinpath(*parts.parts[1:])
                header = tarfile.TarInfo(name)
                header.mode, header.uid, header.gid = entry["mode"], entry["uid"], entry["gid"]
                header.mtime = entry["mtime_ns"] // 1000000000
                if entry["kind"] == "directory":
                    header.type = tarfile.DIRTYPE
                    archive.addfile(header)
                else:
                    raw = _read(source)
                    _need(len(raw) == entry["bytes"] and _sha(raw) == entry["sha256"], "SOURCE_CHANGED_DURING_ARCHIVE")
                    header.size = len(raw)
                    archive.addfile(header, io.BytesIO(raw))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(str(path), 0o600)
    _privacy(path)
    _need(path.stat().st_size <= MAX_ARCHIVE_BYTES, "ARCHIVE_SIZE_LIMIT")


def _verify_archive(path, inventory, destination=None):
    _need(path.stat().st_size <= MAX_ARCHIVE_BYTES, "ARCHIVE_SIZE_LIMIT")
    seen, total = set(), 0
    with tarfile.open(str(path), "r:") as archive:
        for member in archive:
            name = member.name
            _member_path(name)
            _need(name in inventory and name not in seen, "ARCHIVE_MEMBERSHIP_DIFFERS")
            entry = inventory[name]
            _need(not member.linkname and member.sparse is None
                  and set(member.pax_headers) <= {"path", "uid", "gid", "mtime"},
                  "ARCHIVE_SPECIAL_METADATA_PROHIBITED")
            _need(member.uid == entry["uid"] and member.gid == entry["gid"]
                  and member.mode == entry["mode"] and member.mtime == entry["mtime_ns"] // 1000000000,
                  "ARCHIVE_METADATA_DIFFERS")
            seen.add(name)
            if entry["kind"] == "directory":
                _need(member.type == tarfile.DIRTYPE and member.size == 0, "ARCHIVE_TYPE_DIFFERS")
                if destination is not None:
                    _new_directory(destination.joinpath(*PurePosixPath(name).parts))
            else:
                _need(member.type == tarfile.REGTYPE and member.size == entry["bytes"]
                      and 0 <= member.size <= MAX_MEMBER_BYTES, "ARCHIVE_TYPE_OR_SIZE_DIFFERS")
                total += member.size
                _need(total <= MAX_TOTAL_BYTES, "TOTAL_BYTES_LIMIT")
                raw = archive.extractfile(member).read(MAX_MEMBER_BYTES + 1)
                _need(len(raw) == entry["bytes"] and _sha(raw) == entry["sha256"], "ARCHIVE_CONTENT_DIFFERS")
                if destination is not None:
                    _new_file(destination.joinpath(*PurePosixPath(name).parts), raw)
    _need(seen == set(inventory), "ARCHIVE_MEMBERSHIP_DIFFERS")


def _cell(value):
    if value is None:
        return ["null"]
    if type(value) is bytes:
        return ["blob", base64.b64encode(value).decode("ascii")]
    if type(value) is str:
        return ["text", value]
    if type(value) is int:
        return ["integer", str(value)]
    if type(value) is float:
        return ["real", value.hex()]
    raise SnapshotError("SQLITE_VALUE_TYPE_UNSUPPORTED")


def _sqlite_inventory(connection):
    deadline = time.monotonic() + MAX_SQLITE_SECONDS
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    _need(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "SQLITE_INTEGRITY_FAILED")
    _need(connection.execute("PRAGMA foreign_key_check").fetchone() is None, "SQLITE_FOREIGN_KEYS_FAILED")
    schema = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name,sql").fetchall()
    tables, row_count, encoded_bytes = {}, 0, 0
    for name, in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        encoded = []
        quoted = '"' + name.replace('"', '""') + '"'
        columns = {row[1].lower() for row in connection.execute("PRAGMA table_xinfo(" + quoted + ")")}
        alias = next((item for item in ("rowid", "_rowid_", "oid") if item not in columns), None)
        rowid_binding = "not_addressable"
        cursor = None
        if alias is not None:
            try:
                cursor = connection.execute("SELECT " + alias + ",* FROM " + quoted)
                rowid_binding = alias
            except sqlite3.OperationalError:
                # WITHOUT ROWID tables have no hidden identifier. Declared rows
                # and schema remain fully bound; do not invent a row identifier.
                cursor = None
        if cursor is None:
            cursor = connection.execute("SELECT * FROM " + quoted)
        for row in cursor:
            raw = _raw([_cell(value) for value in row])
            row_count += 1
            encoded_bytes += len(raw)
            _need(row_count <= MAX_ROWS and len(raw) <= MAX_ROW_BYTES
                  and encoded_bytes <= MAX_TOTAL_BYTES, "SQLITE_ROW_LIMIT")
            encoded.append(raw)
        tables[name] = {"rows": len(encoded), "sha256": _sha(b"".join(sorted(encoded))),
                        "implicit_rowid_binding": rowid_binding}
    return {"schema_objects": len(schema), "schema_sha256": _sha(_raw(schema)), "tables": tables,
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "application_id": connection.execute("PRAGMA application_id").fetchone()[0]}


def _sqlite_readback(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=5)
    try:
        connection.enable_load_extension(False)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        return _sqlite_inventory(connection)
    finally:
        connection.close()


def _consistent_sqlite(archive_path, destination, inventory):
    capture = destination / "sqlite-capture"
    _new_directory(capture)
    with tarfile.open(str(archive_path), "r:") as archive:
        for member in archive:
            if member.name in {"fox-data/" + name for name in SQLITE_MEMBERS}:
                _need(member.isfile(), "SQLITE_CAPTURE_INVALID")
                raw = archive.extractfile(member).read(MAX_MEMBER_BYTES + 1)
                _need(_sha(raw) == inventory[member.name]["sha256"], "SQLITE_CAPTURE_CHANGED")
                _new_file(capture / PurePosixPath(member.name).name, raw)
    _need((capture / "fox.sqlite3").is_file(), "FOX_SQLITE_REQUIRED")
    target = destination / "sqlite-consistent.sqlite3"
    _new_file(target, b"")
    source, copied = None, None
    try:
        # Only the isolated captured copy may recover WAL/journal contents.
        source = sqlite3.connect(str(capture / "fox.sqlite3"), timeout=5)
        source.enable_load_extension(False)
        source.execute("PRAGMA trusted_schema=OFF")
        source.execute("BEGIN")
        expected = _sqlite_inventory(source)
        copied = sqlite3.connect(str(target), timeout=5)
        deadline = time.monotonic() + MAX_SQLITE_SECONDS
        def progress(status, remaining, total):
            _need(time.monotonic() <= deadline, "SQLITE_COPY_TIMEOUT")
        source.backup(copied, pages=128, progress=progress)
        copied.close()
        copied = None
        source.close()
        source = None
        _need(_sqlite_readback(target) == expected, "SQLITE_COPY_DIFFERS")
    finally:
        if copied is not None:
            copied.close()
        if source is not None:
            source.close()
    for path in capture.iterdir():
        _need(path.name in SQLITE_MEMBERS, "SQLITE_CAPTURE_MEMBER_UNEXPECTED")
        os.chmod(str(path), 0o600)
        _privacy(path)
    os.chmod(str(target), 0o600)
    _privacy(target)
    return expected


def _load(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _need(key not in value, "DUPLICATE_JSON_FIELD")
            value[key] = item
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(SnapshotError("NONFINITE_JSON")))
    _need(type(value) is dict, "JSON_OBJECT_REQUIRED")
    return value


def _backup_artifacts(directory):
    _privacy(directory, True)
    artifacts = {}
    for path in sorted(directory.rglob("*")):
        name = path.relative_to(directory).as_posix()
        if path.is_dir():
            _need(name == "sqlite-capture", "BACKUP_DIRECTORY_UNEXPECTED")
            _privacy(path, True)
            continue
        _need(name in ("roles.tar", "sqlite-consistent.sqlite3", "manifest.json", "completion.json")
              or name.startswith("sqlite-capture/") and name.split("/", 1)[1] in SQLITE_MEMBERS,
              "BACKUP_MEMBER_UNEXPECTED")
        _privacy(path)
        limit = MAX_ARCHIVE_BYTES if name == "roles.tar" else MAX_MEMBER_BYTES
        raw = _read(path, limit)
        artifacts[name] = {"bytes": len(raw), "sha256": _sha(raw)}
    return artifacts


def _verify_material(directory):
    _privacy(directory, True)
    _privacy(directory.parent, True)
    manifest_raw = _read(directory / "manifest.json", MAX_MANIFEST_BYTES)
    manifest = _load(manifest_raw)
    _need(set(manifest) == {"schema_version", "scope", "roles", "inventory", "sqlite_inventory", "artifacts"}
          and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
          and manifest["scope"] == "fox-stopped-snapshot-v1", "BACKUP_MANIFEST_INVALID")
    roles = manifest["roles"]
    _need(type(roles) is list and len(set(roles)) == len(roles)
          and set(roles) <= ROLES and "fox-data" in roles, "BACKUP_ROLES_INVALID")
    _validate_inventory(manifest["inventory"], roles)
    _need(manifest["inventory"].get("fox-data/fox.sqlite3", {}).get("kind") == "file",
          "FOX_SQLITE_REQUIRED")
    artifacts = _backup_artifacts(directory)
    expected = dict(artifacts)
    expected.pop("manifest.json", None)
    expected.pop("completion.json", None)
    _need(expected == manifest["artifacts"] and {"roles.tar", "sqlite-consistent.sqlite3", "sqlite-capture/fox.sqlite3"} <= set(expected),
          "BACKUP_ARTIFACTS_CHANGED")
    _verify_archive(directory / "roles.tar", manifest["inventory"])
    _need(_sqlite_readback(directory / "sqlite-consistent.sqlite3") == manifest["sqlite_inventory"],
          "BACKUP_SQLITE_DIFFERS")
    return manifest, artifacts, _sha(manifest_raw)


def _verify_backup(directory):
    _privacy(directory, True)
    _privacy(directory.parent, True)
    completion_raw = _read(directory / "completion.json", MAX_MANIFEST_BYTES)
    completion = _load(completion_raw)
    _need(set(completion) == {"schema_version", "scope", "manifest_sha256"}
          and type(completion["schema_version"]) is int and completion["schema_version"] == 1
          and completion["scope"] == "fox-stopped-snapshot-complete-v1", "BACKUP_COMPLETION_INVALID")
    manifest, artifacts, manifest_sha = _verify_material(directory)
    _need(manifest_sha == completion["manifest_sha256"], "BACKUP_MANIFEST_CHANGED")
    return manifest, artifacts, _sha(completion_raw)


def backup(roles, destination):
    """Capture explicit stopped roles. Caller must hold scope/idle/operator guards."""
    _privacy()
    _need(hasattr(sqlite3.Connection, "backup"), "SQLITE_BACKUP_API_REQUIRED")
    try:
        _need(type(roles) is dict and set(roles) <= ROLES and "fox-data" in roles, "ROLES_INVALID")
        sources = {role: _path(path) for role, path in roles.items()}
        _need(all(path.is_dir() for path in sources.values()), "ROLE_DIRECTORY_REQUIRED")
        target = _path(destination, False)
        _need(not os.path.lexists(str(target)) and target.parent.is_dir(), "CREATE_ONLY_DIRECTORY_REQUIRED")
        _privacy(target.parent, True)
        _disjoint(list(sources.values()) + [target])
        before = _inventory(sources)
        _need(before.get("fox-data/fox.sqlite3", {}).get("kind") == "file", "FOX_SQLITE_REQUIRED")
        _validate_inventory(before, sorted(sources))
        _new_directory(target)
        _write_archive(sources, before, target / "roles.tar")
        _verify_archive(target / "roles.tar", before)
        sqlite_inventory = _consistent_sqlite(target / "roles.tar", target, before)
        _need(_stable(before, _inventory(sources)), "SOURCE_CHANGED_DURING_BACKUP")
        artifacts = _backup_artifacts(target)
        manifest = {"schema_version": 1, "scope": "fox-stopped-snapshot-v1", "roles": sorted(sources),
                    "inventory": before, "sqlite_inventory": sqlite_inventory, "artifacts": artifacts}
        manifest_raw = _raw(manifest)
        _need(len(manifest_raw) <= MAX_MANIFEST_BYTES, "MANIFEST_SIZE_LIMIT")
        _new_file(target / "manifest.json", manifest_raw)
        verified, _, manifest_sha = _verify_material(target)
        _need(manifest_sha == _sha(manifest_raw), "BACKUP_MANIFEST_CHANGED")
        _need(_stable(before, _inventory(sources)), "SOURCE_CHANGED_BEFORE_COMPLETION")
        completion = {"schema_version": 1, "scope": "fox-stopped-snapshot-complete-v1",
                      "manifest_sha256": _sha(manifest_raw)}
        completion_raw = _raw(completion)
        result = {"schema_version": 1, "scope": "fox-stopped-snapshot-result-v1", "status": "BACKUP_VERIFIED",
                "roles": sorted(sources), "files": sum(entry["kind"] == "file" for entry in before.values()),
                "bytes": sum(entry.get("bytes", 0) for entry in before.values()),
                "manifest_sha256": _sha(manifest_raw), "completion_sha256": _sha(completion_raw),
                "archive_sha256": artifacts["roles.tar"]["sha256"],
                "sqlite_inventory_sha256": _sha(_raw(verified["sqlite_inventory"])),
                "source_unchanged": True, "live_data_restored": False, "scope_idle_operator_guards": "CALLER_REQUIRED"}
        # All verification precedes this final create-only completion marker.
        _new_file(target / "completion.json", completion_raw)
        return result
    except SnapshotError:
        raise
    except Exception:
        raise SnapshotError("BACKUP_FAILED_PARTIALS_PRESERVED") from None


def restore_test(backup_dir, new_destination):
    """Verify trusted private backup and create an independent, non-serving copy."""
    _privacy()
    try:
        source = _path(backup_dir)
        target = _path(new_destination, False)
        _need(source.is_dir() and not os.path.lexists(str(target)) and target.parent.is_dir(),
              "RESTORE_DIRECTORIES_INVALID")
        _disjoint([source, target])
        manifest, original_artifacts, completion_sha = _verify_backup(source)
        _new_directory(target)
        restored = target / "restored"
        _new_directory(restored)
        _verify_archive(source / "roles.tar", manifest["inventory"], restored)
        actual = _inventory({role: restored / role for role in manifest["roles"]})
        _need(set(actual) == set(manifest["inventory"]), "RESTORED_MEMBERSHIP_DIFFERS")
        for name, expected in manifest["inventory"].items():
            observed = actual[name]
            _need(observed["kind"] == expected["kind"]
                  and observed.get("bytes") == expected.get("bytes")
                  and observed.get("sha256") == expected.get("sha256"), "RESTORED_CONTENT_DIFFERS")
            _privacy(restored.joinpath(*PurePosixPath(name).parts), expected["kind"] == "directory")
        sqlite_path = target / "sqlite-restored.sqlite3"
        _new_file(sqlite_path, _read(source / "sqlite-consistent.sqlite3"))
        _need(_sqlite_readback(sqlite_path) == manifest["sqlite_inventory"], "RESTORED_SQLITE_DIFFERS")
        _need(_backup_artifacts(source) == original_artifacts, "ORIGINAL_BACKUP_CHANGED")
        result = {"schema_version": 1, "scope": "fox-isolated-restore-test-v1", "status": "RESTORE_TEST_PASSED",
                  "roles": manifest["roles"], "files": sum(entry["kind"] == "file" for entry in actual.values()),
                  "backup_completion_sha256": completion_sha, "manifest_sha256": original_artifacts["manifest.json"]["sha256"],
                  "sqlite_inventory_sha256": _sha(_raw(manifest["sqlite_inventory"])),
                  "original_backup_unchanged": True, "live_data_restored": False, "services_started": False,
                  "authentication_or_runtime_tested": False}
        _new_file(target / "restore-result.json", _raw(result))
        return result
    except SnapshotError:
        raise
    except Exception:
        raise SnapshotError("RESTORE_TEST_FAILED_PARTIALS_PRESERVED") from None

