# FOX developer project observer

This component is separate from the hosted FOX application. Its tags use
`fox-qa-vX.Y.Z`; changing the observer does not relabel an installed image or
alter the product's version, conversion rules or human-review gates.

## [0.1.1] - 2026-11-05

- Allow the exact same-origin `GET /api/release` used by the version panel.
  Cross-origin, query/fragment variants, mutations and downloads remain denied.
- Let offline browser tests select an existing measured UI bundle/interpreter
  explicitly and serve that bundle's release metadata in the synthetic backend.
  These overrides do not affect live target/deployment selection.
- Verification:47 observer/browser checks passed against the FOX0.4.1 bundle,
  using a synthetic HTTP backend. No live conversion/import or business
  acceptance is established by these offline checks.

Earlier experimental observer source had no separate component release record.
