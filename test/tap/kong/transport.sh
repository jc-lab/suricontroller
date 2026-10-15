#!/usr/bin/env bash
# Runs the Kong plugin's transport test (transport_test.lua) with the
# OpenResty of the Kong image against suritap-mockd and a silent server.
#   test/tap/kong/transport.sh   (KONG_IMAGE, default kong:3.9.1)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${KONG_IMAGE:-kong:3.9.1}"
MOCKD="${SURITAP_MOCKD:-$ROOT/tap/target/release/suritap-mockd}"
[[ -x "$MOCKD" ]] || MOCKD="$ROOT/tap/target/debug/suritap-mockd"
D="$(mktemp -d /tmp/stapk.XXXXXX)"
S="$(mktemp -d /tmp/stapk.XXXXXX)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "${D:?}" "${S:?}"
}
trap cleanup EXIT
printf 'web detect\n' >"$D/policy"
"$MOCKD" --dir "$D" --workers 2 --policy-file "$D/policy" >"$D/mockd.log" 2>&1 &
PIDS+=($!)
python3 "$ROOT/test/tap/kong/silent_server.py" "$S" &
PIDS+=($!)
for _ in $(seq 1 50); do [[ -S "$D/worker-1.stream.sock" && -S "$S/worker-0.stream.sock" ]] && break; sleep 0.1; done
docker run --rm --user "$(id -u):$(id -g)" --entrypoint sh \
    -v "$ROOT/adapters/kong:/plugin:ro" -v "$ROOT/test/tap/kong:/t:ro" -v "$D:$D" -v "$S:$S" \
    "$IMAGE" -c "resty -I /plugin /t/transport_test.lua $D $S"
