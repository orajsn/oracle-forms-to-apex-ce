# Explicit target version selection

This is a configuration and compatibility contract, not an installation status
report or a claim that a candidate has passed a real import/runtime test.

The JSN test registry has two distinct project profiles for the same existing
resource scope. `jsn-native-project-v2` retains APEX 26.1.5.
`jsn-native-project-2616-v1` declares APEX 26.1.6. Both require SQLcl 26.1.2.0,
Database 23.26.4.1.0 and APEXlang MMD 26.1.0+3102. No other patch or mixed tuple
is implicitly supported. These lab choices do not authorize customer targets.

An administrator selects a registered profile in protected installation
configuration. A newly prepared clean-install plan derives its expected tuple
from that validated selection. It never chooses a patch from environment
variables, a browser request or an observed database version. Without an
explicit installation selection, legacy constructors keep their old defaults.

The selected tuple is bound into the plan, allocation and verification profile.
SQLcl checks the declared APEX/Database versions in the same guarded sessions
used for schema preparation and import. Browser-verification inputs must agree
with that exact allocation; one approved tuple cannot borrow another's proof.
Drift stops the operation rather than silently upgrading or downgrading it.

Changing a profile requires a newly measured source/configuration/release and
normal installation admission. It does not patch an immutable bundle, relabel
an earlier receipt or retry an interrupted import. Retain historical profiles,
package bytes and job evidence. Legacy v1 verification remains unchanged;
the explicit version selection applies to the bound v2 verification path.

Registration is only eligibility for checks. A manual-import deliverable must
still have its own successful validation, non-overwriting import and applicable
native runtime evidence for the stated target. Generation, technical proof and
genuine human business acceptance are separate facts.
