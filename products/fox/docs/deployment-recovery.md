# Recovery copies for immutable releases

FOX installations reference provider, release, admission and source-inventory
records. Some layouts keep the last two outside the application bundle or
configuration folder. Capturing only those folders would omit required records.

Hosted recovery plan version 2 adds exactly two required file entries:

- `installation-admission`: the installed admission record's exact path/hash.
- `installation-inventory`: the installed source inventory's exact path/hash.

Both are files, both require SHA-256 pins, and both must match the actual pinned
installation. A neighboring file or a broader parent directory is not covered.
Version-one plans keep their original contract and cannot silently gain these
extra entries. Version two is hosted-only.

## Upgrade without editing the installed source

Current-pair transition plan version 2 requires a `snapshot_adapter` path/hash.
The adapter must be `qa/operator/hosted_snapshot.py` inside the newly measured
bundle and match its verified source inventory. The underlying `snapshot.py`
hash must match that same bundle. It is imported under a separate name; the
older installed source and normal module namespace remain unchanged.

Version-one transitions continue to use their existing reader. This preserves
old plans rather than silently changing their meaning. The new helper uses the
actual current operator lease and installed provider; a plan, Boolean flag or
callback is not capture authority.

Before cutover, inspect exact reference coverage, capture with writers stopped,
prove an isolated restore, and retain the original rows, jobs and operation
receipts. An uncertain capture/restore reply requires observing the same
operation, not replaying it. The isolated restore must not overwrite live data.
These tools do not certify recovery of the separate OPAF repository database.

No recovery plan, successful copy or restore grants business acceptance or
permission to replay conversion/import. Build and verify a fresh measured
release before activating changed source; never relabel old images.
