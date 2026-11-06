# Prepared prototype intake

This route reads redacted Forms business code for a bounded native APEX prototype.
It does not make the original code executable, infer authoritative customer DDL,
or establish business equivalence.

## User flow

1. Keep original FMB/MMB/OLB/PLL binaries local. Use the supported Oracle tooling
   and local FOX preparation/redaction process supplied by the operator.
2. Open a FOX project, choose Upload, then **Open prepared prototype intake**.
3. Choose one to four redacted XML files and their matching redaction receipts.
   For a single file, `receipt.json` is accepted by the UI. For multiple files,
   name each receipt `<XML filename>.redaction.json`.
4. Upload. FOX verifies the exact masked bytes and retains a new source version.
   It starts no AI call or conversion at this point.
5. Review prototype scope, select complete code units, and explicitly confirm
   redaction, the configured external AI route and synthetic-storage scope.
   A changed source or code selection clears consent.
6. Start processing only when the operator-configured route is available. An
   uncertain request is not automatically repeated; check its retained status.

The ordinary readable-source upload remains unchanged. Data-loading scripts do
not gain an exception merely by being renamed XML or supplied with a hash.

## What the receipt establishes

The dedicated intake checks the redacted XML hash/length, complete code-unit hashes,
analysis-only markers, conservative literal policy and retained metadata. XML
comments and processing instructions are rejected rather than silently stripped.
The project records immutable receipt provenance and revalidates it on reads.

Original-file hashes are provenance, not proof that FOX received those unseen
originals. Technical names remain visible. Neither receipt nor source hash is
complete PII certification, external-processing permission or human acceptance.

## Operator status and remaining work

`FOX_PROTOTYPE_PROFILE_FILE` is an additive, protected target-profile envelope;
it must not replace the existing native-project configuration. Credentials use
the existing protected execution tooling and must never be placed in this file.

The worker has a separate prototype branch and retained checkpoints. The internal
converter handoff uses bearer authentication and checks runtime/export capabilities
before those stages. Trusted source/destination authorization and an authenticated
browser adapter are required; absent adapters block instead of fabricating proof.

Version 0.8.0 verifies local intake/assessment/UI. It is not an installed-flow
attestation. Full real-file OPAF review, SQLcl import, authenticated pages, exact
export and complete-package/clean-install proof remain acceptance work. Generated,
technically verified and business accepted are deliberately separate states.
