# Synthetic two-form input fixture

These small CUSTOMERS/ORDERS XML and DDL inputs were authored for FOX tests.
They contain no customer records, credentials, raw Forms binaries or production
database connection. The project specification binds their expected hashes.

They let the existing project-release and clean-engine suites exercise one
application containing two native forms. The suites generate their own temporary
packages and use explicitly synthetic SQLcl/OPAF boundary responses. This folder
does not supply an Oracle-generated export, a Forms Builder conversion proof,
an import certificate or business acceptance. No generated deployment output is
published with these source inputs.
