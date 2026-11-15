# Planned native-prototype operating mode

The existing JSN lab can run native prototype conversions without continuously
running the separate strict-output verifier. This mode does not disable its
configuration or relax per-job source approval, independent review, SQLcl,
import, runtime or package checks. Strict accepted-output remains locked.

An operator may select `native-prototype-strict-stopped-v1` only in an explicitly
reviewed schema-2 transition plan. The plan hash must bind that choice, a current
inert preservation baseline and the existing prototype authority. Default plans
retain the original strict startup and first-idle sequence.

The normal old-state preservation, backup and isolated restore, stopped-candidate
checks, pair start, admission and readiness phases still run. After installing
the new verifier unit, this mode requires it to remain enabled, inactive and
cleanly stopped. It creates only the genuine empty journal's release metadata and
lease file, under the old lease. No verifier session, claim or idle witness is
created or inferred. The same exact metadata is rechecked after HTTPS release.

Successful completion is named
`CURRENT_PAIR_NATIVE_PROTOTYPE_UPGRADE_ACTIVATED_STRICT_STOPPED`, not canonical
strict completion. It does not prove an FMB conversion, SQL export reimport or
business acceptance. Auxiliary workers require their own measured rebind checks.

Do not replay an old transition, recovery tail or failed command. Each upgrade
needs newly measured inputs and a fresh successful inspection. A missing or
changed outcome requires observation; it is not permission to rerun the write.
No new OCI infrastructure, IAM policy, network rule or target tenancy is implied.
