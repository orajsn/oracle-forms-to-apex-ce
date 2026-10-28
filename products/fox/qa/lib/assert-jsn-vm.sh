#!/usr/bin/env bash
# Source only from build/run scripts. Fail closed before VM-local container writes.
set -euo pipefail
expected_compartment='ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
expected_instance='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
metadata=$(curl --fail --silent --show-error --max-time 5 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/)
printf '%s' "$metadata" | python3 -I -B -c 'import json,sys; d=json.load(sys.stdin); ok=d.get("id")==sys.argv[1] and d.get("compartmentId")==sys.argv[2] and d.get("canonicalRegionName")=="us-ashburn-1" and d.get("region")=="iad"; sys.exit(0 if ok else "QA is permitted only on the pinned JSN VM")' "$expected_instance" "$expected_compartment"
unset metadata
test "$(id -u)" -ne 0 || { printf '%s\n' 'Run as the existing opc rootless user, not root.' >&2; exit 2; }
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
