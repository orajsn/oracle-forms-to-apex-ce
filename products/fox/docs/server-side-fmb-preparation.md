# Server-side FMB preparation

This opt-in route lets a business user upload one raw FMB from the project screen.
Oracle Forms tools run on a private configured host. The browser does not need
Forms Builder. Preparation is not an APEX conversion or permission to send code
to an external model.

## User flow

1. Open the project upload screen and choose **Forms FMB file**.
2. Select **Prepare FMB**, then **Check preparation status**.
3. When prepared, select **Add prepared form to project**.
4. Review the inventory, missing dependencies and prototype scope. The separate
   AI-processing approval is still required before conversion can run.

A lost response keeps its request reference. Check that request rather than
submitting another copy. A blocked or interrupted native job is retained for
operator inspection; it is not automatically restarted. If the project source
version changed during preparation, FOX does not overwrite that selection.

## Prerequisites and boundaries

- A supported Linux host with separately installed Oracle Forms tools, native
  libraries, a compatible JDK and the installed FOX Python package/dependencies.
  Oracle media, libraries and JDK distributions are not included in FOX source.
- The implementation has an actual Oracle Forms 14.1.2 Linux FMB preparation
  check. This is not certification for every Forms version, module or platform.
- Explicit Oracle Home, Java Home and private temporary-directory settings.
  `FORMS_API_TK_BYPASS=TRUE` is used for headless native initialization; it is not
  a validation or authentication bypass. No display server is required by the
  tested path.
- One FMB, non-empty and at most 20 MiB, per request. Additional file types and
  dependency bundles are not accepted by this initial hosted route. Use the
  separate supported preparation path for MMB/OLB/PLL; missing dependencies stay
  visible and are never treated as converted.
- Private persistent storage, with five pending jobs and 200 MiB of retained raw
  submissions by default. There is no automatic deletion of source or evidence.
  Operators must reconcile capacity or plan approved archival.

## Connect the existing app and host

Set `FOX_HOSTED_FORMS_QUEUE` in the **app's trusted startup configuration** to an
absolute private queue path visible inside its existing data mount. Mount the
same directory at a known path on the native host. Do not expose it as a static
download directory or accept host paths, commands or Oracle credentials from HTTP.

Run the processor on the compatible native host, not automatically inside an
app image built on a different operating system:

```text
python -m fox.hosted_forms_worker --queue-root <private-host-queue> \
  --oracle-home <installed-oracle-home> --java-home <installed-jdk> \
  --temp-root <private-native-temp>
```

This processes one bounded batch. Add `--poll-seconds 5` for an operator-managed
background worker. Run it with an existing service manager; it opens no HTTP
listener and needs no model or database credentials. Startup checks tool presence
before claiming jobs. Missing configuration must be repaired before enabling the
UI route; setting an environment variable alone is not live readiness evidence.

Prefer one compatible private storage owner. Where a rootless Podman app maps its
user to a subordinate host UID, a tested alternative is to run the host processor
with `podman unshare` and `--handoff-job-owner`. That option requires namespace
root and returns only newly created files within the claimed job to that job
directory's original owner. It does not change parent directories, old jobs or
the Oracle Home. Verify your exact UID mapping and shared paths before using it;
do not grant the public app SSH keys, the Podman socket or arbitrary command access.

## Required activation checks

- Confirm app and host resolve the same private queue and existing resource scope.
- Submit a representative genuine FMB through the installed authenticated UI.
- Observe two successful native exports, an unchanged original and validated
  derivation/redaction records. Verify the app can read the completed result.
- Add it to the correct project; confirm source history and redaction provenance
  persist, while no conversion run or model call is created by preparation.
- Test an invalid FMB and a changed source selection. Neither may appear converted
  or overwrite an existing version. Check an uncertain request without replay.
- Then verify OPAF, SQLcl, APEX import, runtime and export separately. Passing this
  preparation stage does not prove any of those downstream stages.

The original, native exports and effective XML are private evidence. Only the
strictly validated redacted document is adopted into project history. Retained
technical names can still be sensitive; redaction is not a guarantee that all
personal/customer information is removed. The source owner must approve the
actual processing boundary before external AI use.
