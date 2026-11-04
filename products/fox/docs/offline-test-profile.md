# Legacy offline test profile

The checkout excludes locally configured runtime files. Some legacy operator
unit tests deliberately hash `deployment/native-beta-profile.json`; that file
must exist even though the tests forbid external execution.

In a disposable source-test checkout, use the project's Python environment:

```sh
python -B tools/prepare_test_profile.py
python -B tools/prepare_test_profile.py --apply
```

The first command only inspects. The second creates the missing file from the
already registered, nonsecret legacy test target. It never overwrites a
different configured file. Do not delete or replace a real configuration to
make this command succeed; use a disposable checkout instead.

This is test setup, not installation, current-target selection or connection
validation. It creates no credentials and makes no network, OCI, database or
model calls. A generated file does not mean that FOX is installed or ready.
Keep it out of commits, and keep the original historical manifests intact.
For installed project verification, use the explicitly selected protected
project target, not this legacy test helper.
