# External software and attribution

The repository's root `LICENSE.txt` and attribution remain unchanged. FOX source
does not include installed dependency trees, Oracle installers or customer code.

Python/JavaScript dependencies are declared in `fox/requirements-lock.txt`,
`fox/package-lock.json`, `converter/pyproject.toml`, `converter/requirements.txt`
and `qa/package-lock.json`. They retain their own licenses and notices. Retrieve
and review the package metadata/notices for the exact locked distribution before
redistributing a built product; this source list is not a replacement license
bundle for a binary distribution. In particular, defusedxml identifies the Python
Software Foundation license in its package metadata.

Oracle Forms, Java, SQLcl, Oracle Database/APEX and OPAF remain separately
obtained prerequisites under applicable Oracle terms. Use of an installed tool
does not imply permission to redistribute it. The APEXlang source resources
reference APEX's built-in theme; no Oracle installer or vendor runtime is bundled.

No production migration, Oracle Support entitlement, trademark license or Oracle
product endorsement is established by this development snapshot.
