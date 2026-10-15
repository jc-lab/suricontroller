#!/usr/bin/env bash
# suritap phase-1 validation against a real Suricata 8.0.x.
#
#   SURICATA_PREFIX=/opt/suricata SURICATA_SRC=~/src/suricata-8.0.7 test/tap/run.sh [--bench]
#
# SURICATA_PREFIX  installed Suricata (bin/suricata, bin/suricatasc, etc/suricata/*.config)
# SURICATA_SRC     the configured source tree it was built from (plugin headers)
# SURICATA_EXTRA_INCLUDE  optional extra include dirs for the plugin build (':'-separated)
# ET_RULES_DIR     optional directory with ET Open *.rules for the ET benchmark
# WORK             scratch directory (default /tmp/suritap-test; keep it short,
#                  UNIX socket paths are limited to 108 bytes)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${SURICATA_PREFIX:?set SURICATA_PREFIX}"
: "${SURICATA_SRC:?set SURICATA_SRC}"
WORK="${WORK:-/tmp/suritap-test}"
BENCH=0
[[ "${1:-}" == "--bench" ]] && BENCH=1

# shellcheck source=test/tap/lib.sh
source "$ROOT/test/tap/lib.sh"

log "build"
build_all

MAIN="$WORK/main"
log "functional checks (2 workers, IPS, tap.rules)"
render main -e 's/^  threads: 2/  threads: 2/'
start main 2
"$PROBE" check -dir "$MAIN/run" || fail "functional checks"
log "second run (reuses the same client ports: stale flows must not interfere)"
"$PROBE" check -dir "$MAIN/run" -only tuple-reuse || fail "tuple reuse"

log "non-blocking rule reload"
"$PROBE" check -dir "$MAIN/run" -group reload-before || fail "reload-before"
echo 'drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"TAP reloaded rule"; flow:established,to_server; http.uri; content:"/reloaded-rule"; sid:9000010; rev:1;)' >>"$MAIN/rules/tap.rules"
reload main
"$PROBE" check -dir "$MAIN/run" -group reload-after || fail "reload-after"
sed -i '/9000010/d' "$MAIN/rules/tap.rules"
reload main
"$PROBE" check -dir "$MAIN/run" -group reload-before || fail "reload removal"

log "client crash cleanup"
"$PROBE" hold -dir "$MAIN/run" -conns 25 -name crashme >"$WORK/hold.log" 2>&1 &
HOLD=$!
for _ in $(seq 1 40); do grep -q holding "$WORK/hold.log" && break; sleep 0.25; done
kill -9 "$HOLD"
wait "$HOLD" 2>/dev/null || true
sleep 1
grep "('crashme') closed" "$MAIN/log/suricata.log" || fail "sessions of the killed client were not closed"
kill -0 "$(cat "$MAIN/run/suricata.pid")" || fail "suricata died"
"$PROBE" check -dir "$MAIN/run" -only http-uri-drop-ipv4 || fail "check after crash"

log "flow timeouts while workers are idle"
sleep 8
timeouts="$(python3 - "$MAIN/log/eve.json" <<'EOF'
import json, sys
n = 0
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("event_type") == "flow" and e.get("suritap", {}).get("client") == "crashme" \
            and e["flow"].get("reason") == "timeout":
        n += 1
print(n)
EOF
)"
echo "flow records of the killed client's connections: $timeouts/25"
[[ "$timeouts" == 25 ]] || fail "expected 25 timed out flows"

log "EVE enrichment"
python3 - "$MAIN/log/eve.json" <<'EOF' || fail "EVE enrichment"
import json, sys
alerts = [json.loads(l) for l in open(sys.argv[1]) if '"event_type":"alert"' in l]
ok = [a for a in alerts if a.get("suritap", {}).get("cid") and a["suritap"].get("client") == "suritap-probe"]
print(f"{len(ok)}/{len(alerts)} alerts carry suritap metadata, e.g. {ok[0]['suritap'] if ok else None}")
sys.exit(0 if alerts and len(ok) == len(alerts) else 1)
EOF
stop main
if grep -E " Error: " "$MAIN/log/suricata.log"; then fail "errors in suricata.log"; fi

log "exception policy (app-layer parser error, drop-flow)"
render exception -e 's/^exception-policy: auto/exception-policy: drop-flow/'
start exception 2
"$PROBE" check -dir "$WORK/exception/run" -group exception || fail "exception policy"
stop exception

if [[ "$BENCH" == 1 ]]; then
    bench_profile=(-e 's/^  bypass: yes/  bypass: no/' -e 's/^    depth: 1mb/    depth: 0/'
        -e 's/^  threads: 2/  threads: 4/' -e 's/^  idle-ms: 100/  idle-ms: 100\n  spin-us: 50/')
    log "benchmark: tap.rules, 4 workers, depth 0, spin 50us"
    render bench "${bench_profile[@]}"
    start bench 4
    for c in 1 16 64; do
        echo "-- $c connection(s)"
        "$PROBE" bench -dir "$WORK/bench/run" -conns "$c" -requests $((32000 / c)) -pings $([[ $c == 1 ]] && echo 3000 || echo 0) -spin 50us
    done
    stop bench
    if [[ -n "${ET_RULES_DIR:-}" ]]; then
        log "benchmark: ET Open + tap.rules, 4 workers"
        render et "${bench_profile[@]}" -e 's/^  - tap.rules/  - et-all.rules\n  - tap.rules/'
        cat "$ET_RULES_DIR"/*.rules >"$WORK/et/rules/et-all.rules"
        start et 4
        grep "rules successfully loaded" "$WORK/et/log/suricata.log" | tail -1
        "$PROBE" check -dir "$WORK/et/run" -only uri-drop || fail "checks with ET Open"
        for c in 1 16 64; do
            echo "-- $c connection(s)"
            "$PROBE" bench -dir "$WORK/et/run" -conns "$c" -requests $((30000 / c)) -pings 0 -spin 50us
        done
        stop et
    fi
fi

log "summary"
if [[ "$FAILED" -gt 0 ]]; then
    echo "$FAILED failure(s)"
    exit 1
fi
echo "ALL PASSED"
