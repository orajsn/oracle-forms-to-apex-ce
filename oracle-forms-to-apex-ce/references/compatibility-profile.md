# Known-Good POC Profile

Use this profile for repeatable CE demonstrations unless the target environment requires another supported combination.

| Component | Tested profile | Platform | Required evidence |
|---|---|---|---|
| Python | 3.10 or newer | Windows, Linux, macOS | `python --version`; standard library available |
| Oracle Forms Builder | 14.1.2 Standalone | Windows or supported Linux | `frmf2xml`, `frmxmlv`, and Builder installation verified |
| Java | 21 | Target-certified platform | `java -version` and certified compatibility checked |
| Oracle AI Database Free | 26ai, database 23.26.0 or newer | Supported database platform | Database and PDB open; local POC only |
| Oracle APEX | 26.1 | Local or OCI target | `APEX_260100` valid or target reports 26.1 |
| ORDS | 26.1.1 or newer | Target environment | Runtime URL returns HTTP success |
| SQLcl | 26.1 | Windows, Linux, macOS, Unix | `apex validate`, `apex import`, and export commands available |

## Platform routes

- Windows/Linux with Forms tools: convert binaries locally, then continue with the portable core.
- macOS: use readable XML/PLD/SQL directly or submit binaries to an explicitly approved Windows/Linux conversion worker. SQLcl validation can run on macOS.
- Any platform without Forms tools: classify binary conversion as `MISSING`; do not parse binary modules heuristically.

## Installation order

1. Confirm OS certification, memory, disk, privileges, and ports.
2. Install Python 3.10 or newer.
3. Install a certified JDK outside the Oracle Home.
4. On Windows or supported Linux, obtain Oracle Forms installation media from an approved Oracle source and configure Standalone Forms Builder in its own empty Oracle Home.
5. Install or reuse the approved Oracle Database/APEX environment, locally or on OCI.
6. Install and configure ORDS where required.
7. Install SQLcl and run `skills sync` when the Oracle APEX skill set is needed.
8. Run `scripts/preflight.py` and record evidence.

## Official sources

- Forms 14.1.2 preparation: https://docs.oracle.com/en/middleware/developer-tools/forms/14.1.2/install-fnr/preparing-install.html
- Forms 14.1.2 installer platforms: https://docs.oracle.com/en/middleware/developer-tools/forms/14.1.2/install-fnr/starting-oracle-forms-installer.html
- Fusion Middleware requirements: https://docs.oracle.com/en/middleware/fusion-middleware/14.1.2/sysrs/system-requirements-and-specifications.html
- APEX 26.1 requirements: https://docs.oracle.com/en/database/oracle/apex/26.1/htmig/apex-installation-requirements.html
- SQLcl installation: https://docs.oracle.com/en/database/oracle/apex/26.1/aeadm/downloading-and-installing-sqlcl.html
- Oracle APEX skills: https://github.com/oracle/skills

Refresh official documentation before changing the pinned profile or making supportability claims.
