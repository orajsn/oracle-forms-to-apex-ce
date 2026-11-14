# Retrospective FOX changelog

**Added 14 November 2026.** These entries backfill public FOX commits that did
not update a changelog in the same commit. Dates are the original Git-recorded
committer dates, not newly asserted push, deployment or acceptance dates.
The summaries describe source changes only; no old test result is invented.
No commit timestamp, tag or history has been rewritten, and no private history
or customer source has been imported.

Audit boundary: source commit
[`4d7ec7b`](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/4d7ec7b8687119581ef430e182555408a8b89ae0)
(`fox-v0.22.16`). All **51** published `fox-v…` tags already have matching dated
entries in the [main changelog](../CHANGELOG.md). The **32** additional entries
below cover commits with no changed `CHANGELOG.md` file. They are not newly
invented software versions. Component changelogs retain their separate history.

| Original date | Source change | Original commit |
| --- | --- | --- |
| 2026-10-27 | Add the public multi-form FOX development snapshot. | [577d5f8](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/577d5f8e752da0ebab8389085a5c0513fbffc595) |
| 2026-10-27 | Avoid redundant cutover lease reads within the freshness window. | [266eef7](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/266eef733b51cdb55c89d240d0f6cca493540822) |
| 2026-10-27 | Validate retained legacy snapshots without relabelling or replay. | [b916c43](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/b916c4349c095d7c2503874eb8c24085cc6e71ee) |
| 2026-10-27 | Strengthen forward-startup checks and protected QA login. | [a5a2fc1](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/a5a2fc1a10011340690be511c4536c6022228d5a) |
| 2026-10-27 | Prepare verifier working directories and correct OCI preflight. | [79157df](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/79157dfd5a57b5b98c7cc6835462a2143dd01672) |
| 2026-10-27 | Include shared project-QA dependencies in converter images. | [7f4cfce](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/7f4cfce943f8414dcc3bf669a216f4875f39e810) |
| 2026-10-27 | Show verifier attention without replaying conversion work. | [ce6756e](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/ce6756e105704cf0011ec842d1b287c698e900b5) |
| 2026-10-28 | Add offline corrective-image builds against a pinned lab deployment. | [6d4b707](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/6d4b707ccb4298bd17bb59ca3c8294a27cdc4bca) |
| 2026-10-28 | Add read-only installation discovery and check-first installation guidance. | [49fcc93](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/49fcc936a1082b9a1e6c929e0c16b51c9b62ca63) |
| 2026-10-29 | Connect the single-folder installer to the existing storage lifecycle. | [fea4da1](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/fea4da1f3efae5d4eb6cf76fda8a16c44677cb71) |
| 2026-10-29 | Add a loopback browser setup wizard over the storage lifecycle. | [11df201](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/11df201a873e32fac8742278d5b387662b0161c8) |
| 2026-10-29 | Add isolated Linux setup-runtime preparation and launcher. | [ec49595](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/ec49595122a5aec10fbf3694cfb295772913dcbb) |
| 2026-10-29 | Add guided protected access and OPAF configuration. | [4d38963](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/4d389633ea15cdedda5a4aac1144b3315b66df1b) |
| 2026-10-29 | Bind the fresh queue adapter to startup checks and the existing dispatcher. | [e096411](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/e0964116848f307c11bf3a287a592d67aaab58da) |
| 2026-10-29 | Select fresh clean-install transports with bound runtime checks. | [59c2ebf](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/59c2ebf20913ee0c771d94764181494c664395e2) |
| 2026-11-04 | Recognize Oracle Forms Coordinate layout metadata. | [ccd0aed](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/ccd0aed13606055eac184fed138714bc2c6ae9ad) |
| 2026-11-04 | Define product and business-user UI feature goals. | [c3120f1](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/c3120f1f0386010a984d330fba457ffe39cdd475) |
| 2026-11-04 | Add source-linked missing-dependency and package guidance. | [aa9e29a](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/aa9e29a7cc1da8d61bc1b91d276fa1c54beed906) |
| 2026-11-04 | Avoid false package gaps caused by whitespace and supplied built-in names. | [6e523c8](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/6e523c8ab46e86a82391597cfeadc10e8dd854af) |
| 2026-11-04 | Preserve stopped precheck failures without claiming QA success or replaying them. | [a70e4e5](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/a70e4e5bef1152e24de6396d6c05f2f558083df4) |
| 2026-11-05 | Bind clean verification to explicitly selected APEX patch profiles. | [8391d5a](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/8391d5a4529057b50d07c9fc4175ebe710f1ef3c) |
| 2026-11-05 | Synchronize the converter assessment copy with reviewed source. | [c4f6773](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/c4f6773b06addf6680047233fd52a580906d4a3a) |
| 2026-11-05 | Admit closed prechecks and preserve accurate journal I/O failures. | [f040008](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/f0400082a20f88f1fbaaebc773eeffe5e98dc0d3) |
| 2026-11-05 | Prepare current-pair upgrades with pinned installation and preserved ancestry. | [4e96e56](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/4e96e56e9faa00dd0b7da108c81d37bee48f30ea) |
| 2026-11-05 | Add forward transition of the current pair and selected-profile readiness checks. | [7b22cc2](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/7b22cc2365e0a982c3c9fa4fd2602f40861f619c) |
| 2026-11-05 | Check profile labels and observe actual idle claims before transition. | [3d825fa](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/3d825fa8c0871829632d5056424312b2b23e8f1c) |
| 2026-11-05 | Include the complete project-QA handoff dependencies. | [8095dc3](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/8095dc3f09e85ad4c2d855315915847a41a80f4c) |
| 2026-11-05 | Explain project readiness without false configuration errors. | [9bbf5f7](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/9bbf5f7853f7dcc9be6144b7a870e3fbd3b92b39) |
| 2026-11-05 | Classify retained project-QA handoff failures without replay. | [1c7aca2](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/1c7aca2ecee3b057e08fddf1b05eb0f34a9b7e9d) |
| 2026-11-05 | Preserve closed QA-stage failures across guarded upgrades. | [040fc1f](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/040fc1f44ee404dd28e70347133b5881e597e535) |
| 2026-11-05 | Validate retained artifact paths across Windows and Linux. | [33f0da0](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/33f0da0a379749607771815a70c427cb6a7e4b3c) |
| 2026-11-13 | Clarify the metadata-only verifier observer boundary. | [59fbac3](https://github.com/orajsn/oracle-forms-to-apex-ce/commit/59fbac384b5d584d8d3dcf8717984e9fa455b078) |

## How coverage was checked

Read-only Git history was inspected for the public `products/fox/` subtree.
For each commit through the audit boundary, the changed-file list was checked
for a `CHANGELOG.md` file. Every row above links a real commit in that ancestry.
The 51 software tags were separately compared with the main changelog's version
headings and recorded dates. This audit does not infer when a push reached GitHub
or when a source change was deployed.

For future updates, follow the [release policy](release-policy.md): a dated
documentation entry for documentation-only work, or the appropriate versioned
product/component entry for a software increment.
