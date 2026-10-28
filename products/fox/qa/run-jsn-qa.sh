#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$#" -lt 4 ] || [ "$#" -gt 8 ]; then
  printf '%s\n' 'Usage: run-jsn-qa.sh ABS_RECEIPT ABS_PROFILE ABS_CREDENTIAL_JSON ABS_OUTPUT_DIR [ABS_PACKAGE_ZIP|-] [ABS_NATIVE_SPEC|-] [ABS_IMPORT_RECEIPT|-] [ABS_VERIFICATION_PROFILE]' >&2
  exit 2
fi
qa_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$qa_dir/lib/assert-jsn-vm.sh"
for file in "$1" "$2" "$3"; do
  [[ "$file" = /* ]] && test -f "$file" && ! test -L "$file" || { printf '%s\n' 'Inputs must be absolute regular files, not symlinks.' >&2; exit 2; }
done
[[ "$4" = /* ]] && ! test -L "$4" || { printf '%s\n' 'Output must be an absolute directory, not a symlink.' >&2; exit 2; }
# Only the dedicated QA secret is mounted. Never mount an entire OCI/.ssh/DPAPI directory.
secret_mode=$(stat -c '%a' "$3")
case "$secret_mode" in 400|600) ;; *) printf '%s\n' 'QA credential file must have mode 400 or 600.' >&2; exit 2;; esac
test "$(stat -c '%u' "$3")" = "$(id -u)" || { printf '%s\n' 'QA credential must belong to the rootless operator.' >&2; exit 2; }
image='localhost/fox-native-qa:pw1.64.0'
podman image exists "$image" || { printf '%s\n' 'QA image is not installed. Run the approved build script first.' >&2; exit 2; }
qa_image_id=$(podman image inspect --format '{{.Id}}' "$image")
qa_run_image="$image"
qa_version=$(jq -er '.schema_version | select(. == 1 or . == 2)' "$1")
if [ "$qa_version" = 2 ]; then
  [ "${FOX_QA_INSPECT_ONLY:-}" != 1 ] || { printf '%s\n' 'Inspect-only v2 is not a write authorization.' >&2; exit 2; }
  qa_run_image="$qa_image_id"
  [ "$#" = 8 ] || { printf '%s\n' 'V2 requires all exact package/spec/import and verification profile inputs.' >&2; exit 2; }
  for file in "$5" "$6" "$7" "$8"; do
    [[ "$file" = /* ]] && test -f "$file" && ! test -L "$file" || { printf '%s\n' 'V2 inputs must be absolute regular files.' >&2; exit 2; }
  done
  # Fixed private state, not caller-controlled: an allocation is never silently replayed.
  qa_dispatch='/home/opc/.config/fox-qa/dispatch-v2'
  test ! -L "$qa_dispatch" || exit 2
  mkdir -m 700 -p -- "$qa_dispatch"
  test "$(stat -c '%a:%u' "$qa_dispatch")" = "700:$(id -u)" || { printf '%s\n' 'V2 dispatch state is not private/owned by this operator.' >&2; exit 2; }
elif [ "$#" = 8 ]; then
  printf '%s\n' 'A v1 receipt must not receive v2 inputs.' >&2; exit 2
fi
mkdir -p -- "$4"
args=(--rm --init --pull=never --name "fox-native-qa-$(date +%s)-$$"
  --userns=keep-id --user "$(id -u):$(id -g)" --read-only --cap-drop=all
  --security-opt=no-new-privileges --ipc=private --shm-size=256m
  --cpus=1 --memory=1536m --pids-limit=256
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777
  --env FOX_QA_TARGET_RECEIPT=/run/qa/target.json --env FOX_QA_PROFILE=/run/qa/profile.json
  --env FOX_QA_CREDENTIAL_FILE=/run/secrets/apex.json --env FOX_QA_OUTPUT_DIR=/results
  --volume "$1:/run/qa/target.json:ro,Z" --volume "$2:/run/qa/profile.json:ro,Z"
  --volume "$3:/run/secrets/apex.json:ro,Z" --volume "$4:/results:Z")
if [ "$qa_version" = 2 ]; then
  args+=(--env FOX_QA_VERIFICATION_PROFILE=/run/qa/verification-profile.json
    --env FOX_QA_DISPATCH_DIR=/dispatch --env "FOX_QA_IMAGE_ID=$qa_image_id"
    --volume "$8:/run/qa/verification-profile.json:ro,Z" --volume "$qa_dispatch:/dispatch:Z")
fi
if [ "${FOX_QA_INSPECT_ONLY:-}" = 1 ]; then args+=(--env FOX_QA_INSPECT_ONLY=1); fi
if [ "$#" -ge 5 ] && [ "$5" != - ]; then
  [[ "$5" = /* ]] && test -f "$5" && ! test -L "$5" || { printf '%s\n' 'Package must be an absolute regular ZIP file.' >&2; exit 2; }
  args+=(--env FOX_QA_PACKAGE=/run/qa/package.zip --volume "$5:/run/qa/package.zip:ro,Z")
fi
if [ "$#" -ge 6 ] && [ "$6" != - ]; then
  [[ "$6" = /* ]] && test -f "$6" && ! test -L "$6" || { printf '%s\n' 'Native spec must be an absolute regular file.' >&2; exit 2; }
  args+=(--env FOX_QA_NATIVE_SPEC=/run/qa/native-spec.json --volume "$6:/run/qa/native-spec.json:ro,Z")
fi
if [ "$#" -ge 7 ] && [ "$7" != - ]; then
  [[ "$7" = /* ]] && test -f "$7" && ! test -L "$7" || { printf '%s\n' 'Import receipt must be an absolute regular file.' >&2; exit 2; }
  args+=(--env FOX_QA_IMPORT_RECEIPT=/run/qa/import-receipt.json --volume "$7:/run/qa/import-receipt.json:ro,Z")
fi
printf '%s\n' 'QA starts on demand, publishes no ports, retains synthetic rows and stops after 15 minutes.'
printf '%s\n' 'Requested resource caps: 1 CPU / 1536 MiB / 256 PIDs. Rootless cgroup v1 may not enforce these caps.'
timeout --signal=TERM --kill-after=20s 900s podman run "${args[@]}" "$qa_run_image"
