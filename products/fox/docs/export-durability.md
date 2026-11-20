# What makes a FOX export recoverable?

A completed XML-mapping run should return the same ZIP after a restart or renderer
upgrade. Reopening a result is not a new conversion. A new parser may reject a
module that an older version accepted; that decision applies to new work and must
not retroactively invalidate the old package. Never serve an altered ZIP or
relabel old behavior as converted by a newer engine.

## What must survive

Keep the FOX database (project ownership, selected source, run, consent and
completion events) and the matching job files (snapshot, candidate and final
ZIPs, result receipt, validation log). Copying the final ZIP alone lets someone
keep a file; it cannot restore authenticated project history or the evidence
needed for FOX to serve that file. A complete service restore also requires
its configuration, protected credentials, and other project data such as the
Forms preparation queue. This checkpoint is not a full host disaster-recovery test.

The 0.38.2 change is about the saved artifact, not the current source assessment:
the latter can still use today's parser and mark the current source unavailable
for new work. History still opens saved artifacts one by one. A cheap, paginated
history summary is a distinct follow-up; list performance has not been benchmarked
for this version.

## Next iteration for a hosted installation (proposal, not enabled)

1. Keep the local storage implementation for portable installs. Implement an
   optional OCI publisher for validated exports. Use a private versioned bucket,
   a per-project/run object key with the package hash, and application access
   restricted to the intended bucket. Do not make an object public to offer a download.
2. Persist publication intent **before** uploading. Verify object bytes and size;
   retain the object key, exact version ID, SHA-256 and validation-receipt binding
   in a recoverable run record. Show **Ready** only after the verified publication
   is committed. The bucket is not a replacement for project authorization.
3. After a timeout between storing bytes and recording their version, reconcile the
   exact pending key and content first. Reuse a verified prior upload. If absent,
   retry only publication. If conflicting, block with an actionable operator error.
   Never rerun the converter, SQLcl or an AI model to fix a storage failure.
4. Design and test a consistent backup of the project database and its evidence.
   Include object versions in the backup inventory; keep retention policies from
   removing versions referenced by saved runs. Restore into an empty test instance;
   verify the original owner can retrieve identical bytes and another owner cannot.
5. Before enabling it, test storage outages, crash-after-PUT, DB commit failure,
   wrong or missing version, content mismatch and recovery without duplicate runs.
   Use synthetic fixtures first. Export ZIPs include original XML; selecting
   a customer bucket/tenancy, credentials and retention is a deployment decision,
   not a default migration of hosted customer artifacts.

For large histories, keep lightweight authenticated summary records and fetch
full evidence when opening an individual result. Track the cost of listing and
downloading separately. For admission, measure work done under the SQLite write
lock before changing it; keep duplicate-request and source-version checks atomic.
