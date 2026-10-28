# Protected access and connection inputs

The Linux setup wizard now continues from verified storage to a real protected
settings step. It saves formats read by the existing project adapter; it does
not test connectivity or start services. Current selectable target is the
registered JSN synthetic-test profile. Customer onboarding remains a release
gate; the UI does not accept an arbitrary production target or infer authority.

After preparing or rechecking the same storage folder, enter a FOX login name,
new FOX password and the existing OPAF login/password. Review the target label
and explicitly approve saving. The FOX password is stored in the existing
scrypt verifier format. The OPAF password must remain recoverable for the app's
login client; it is protected by owner-private server storage, not described as
encrypted at rest. A fresh random internal MCP bearer token is created by the
installer, never requested from the operator or copied from an OCI signing key.
Existing OPAF/database passwords are not changed.

All files are created under the chosen instance's `configuration` directory:

- `target-profile.json`: the exact registered target snapshot.
- `opaf-profile.json`: the actual paired project mapper/reviewer profile.
- `opaf/client.json`: actual protected client format, including the shared
  internal converter token; only this directory is intended for the FOX mount.
- `private/fox-access.json`: FOX username and password verifier.
- `private/converter-token`: matching token for the protected service binder.
- `intent.json` and `complete.json`: private source/storage-bound records and
  integrity checks. They are not service admission or independent signatures.

New directories are owner-only 0700 and files 0600. The entire configuration
root must never be mounted into the public app: only the required profile and
OPAF subdirectory belong in its existing read-only mounts. Private access/token
files and receipts belong to the installer/service operator. The future service
binder still needs implementation and independent runtime proof.

Repeated setup verifies and reuses the exact completed settings without changing
credentials, identity or files. It is not password rotation. Partial writes,
unknown files, changed contents or linked paths stop for inspection, preserve
the attempt, and do not retry/repair it. After an uncertain browser response,
use read-only Recheck saved state. A validation error before any attempt allows
correction after recheck; no network/model request is replayed.

Passwords stay in the authenticated loopback request and protected files, not
arguments, URLs, browser storage, response JSON or access logs. Password inputs
are cleared after submission. Do not send real passwords in chat or test output.
An approved remote setup needs protected loopback access; this administrator
HTTP listener is not a public deployment endpoint.

`CONNECTION_INPUTS_SAVED_NOT_TESTED` explicitly leaves connectivity, SQLcl saved
connection/wallet setup, protected verifier credentials, Forms tooling, service
installation/admission and full multi-form output unproved. No Oracle connection,
OCI write, model inference or password rotation happens in this step.

Developer tests use disposable synthetic credentials and genuine nonroot Linux
storage. `tests/test_fox_installer_connections.py` also loads the produced files
through the real project adapter without making a network call. Set
`FOX_SETUP_TEST_CONNECTIONS=1` for the optional existing-browser journey; it
performs one settings submission and read-only recheck, clears password inputs,
and closes its owned listener. These tests do not establish customer readiness.
