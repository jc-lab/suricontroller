#!/usr/bin/env bash
# suritap phase-3 validation: Kong (official image, DB-less) with the
# suritap Lua plugin (adapters/kong) in front of a real Suricata 8.0.x.
#
#   SURICATA_PREFIX=/opt/suricata SURICATA_SRC=~/src/suricata-8.0.7 test/tap/kong.sh [--bench]
#
# KONG_IMAGE Kong image (default kong:3.9.1); runs with host networking as
#            the current user so that it can reach the worker sockets
# WORK       scratch directory (default /tmp/suritap-kong)
# PORT_BASE  local ports PORT_BASE+43 (Kong), +80/+81 (backend); default 29500 (below the ephemeral port range)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${SURICATA_PREFIX:?set SURICATA_PREFIX}"
: "${SURICATA_SRC:?set SURICATA_SRC}"
WORK="${WORK:-/tmp/suritap-kong}"
BENCH=0
for a in "$@"; do
    case "$a" in
    --bench) BENCH=1 ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
    esac
done
IMAGE="${KONG_IMAGE:-kong:3.9.1}"
PORT_BASE="${PORT_BASE:-29500}"
P_HTTP=$((PORT_BASE + 80)) P_TCP=$((PORT_BASE + 81)) P_KONG=$((PORT_BASE + 43))
CONTAINER="suritap-kong-test-$$"

# shellcheck source=test/tap/lib.sh
source "$ROOT/test/tap/lib.sh"
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; cleanup' EXIT

log "build"
build_all
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE"
docker run --rm --entrypoint kong "$IMAGE" version

log "start Suricata, backend and Kong"
# Kong listens on 127.0.0.2 (the "home" listener); clients come from
# 127.0.0.1, which is external like real clients.
LISTEN=127.0.0.2
render main -e 's/^  bypass: yes/  bypass: no/' -e 's/^    depth: 1mb/    depth: 0/' \
    -e 's#^    HOME_NET: "\[#    HOME_NET: "[127.0.0.2/32,#'
start main 2
SOCK="$WORK/main/run"
EVE="$WORK/main/log/eve.json"

"$PROBE" backend -http 127.0.0.1:$P_HTTP -tcp 127.0.0.1:$P_TCP >"$WORK/backend.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do grep -q ready "$WORK/backend.log" 2>/dev/null && break; sleep 0.1; done

K="$WORK/kong"
rm -rf "$K"
mkdir -p "$K"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$K/key.pem" -out "$K/cert.pem" -days 2 -subj "/CN=app.example" \
    -addext "subjectAltName=DNS:app.example,DNS:strict.example,DNS:plain.example" 2>/dev/null
indent() { sed 's/^/      /' "$1"; }
cat >"$K/kong.yml" <<EOF
_format_version: "3.0"
certificates:
  - cert: |
$(indent "$K/cert.pem")
    key: |
$(indent "$K/key.pem")
    snis:
      - name: app.example
      - name: strict.example
      - name: plain.example
services:
  - name: backend
    url: http://127.0.0.1:$P_HTTP
    routes:
      - name: app
        hosts: [app.example]
        plugins:
          - name: suritap
            config:
              socket_dir: $SOCK
              endpoint: websecure
              mode: prevent
              timeout: 1000
      - name: strict
        hosts: [strict.example]
        plugins:
          - name: suritap
            config:
              socket_dir: $SOCK
              endpoint: strict
              mode: prevent
              response: prevent
              fail_policy: closed
              timeout: 1000
          - name: suritap-response
      - name: plain
        hosts: [plain.example]
EOF
docker run -d --name "$CONTAINER" --network host --user "$(id -u):$(id -g)" \
    -v "$ROOT/adapters/kong:/plugin:ro" -v "$K:$K:ro" -v "$SOCK:$SOCK" \
    -e KONG_PREFIX=/tmp/kong -e KONG_DATABASE=off -e KONG_DECLARATIVE_CONFIG="$K/kong.yml" \
    -e KONG_PLUGINS=bundled,suritap,suritap-response -e KONG_LUA_PACKAGE_PATH="/plugin/?.lua;;" \
    -e KONG_PROXY_LISTEN="$LISTEN:$P_KONG ssl http2" -e KONG_ADMIN_LISTEN=off \
    -e KONG_NGINX_WORKER_PROCESSES=2 -e KONG_PROXY_ACCESS_LOG=off -e KONG_PROXY_ERROR_LOG=/dev/stderr \
    -e KONG_LOG_LEVEL=notice \
    "$IMAGE" >/dev/null
CURL=(curl -sk --max-time 10 -o "$K/body" -w '%{http_code} %{http_version}'
    --resolve app.example:$P_KONG:$LISTEN --resolve strict.example:$P_KONG:$LISTEN --resolve plain.example:$P_KONG:$LISTEN)
for _ in $(seq 1 150); do
    [[ "$("${CURL[@]}" https://plain.example:$P_KONG/ready || true)" == 200* ]] && break
    sleep 0.2
done
docker logs "$CONTAINER" 2>&1 | grep -iE "error|warn" | grep -v "cannot reach" | head -5 || true

# req NAME EXPECTED_STATUS curl-args...
req() {
    local name="$1" want="$2" got
    shift 2
    got="$("${CURL[@]}" "$@" || true)"
    if [[ "${got%% *}" == "$want" ]]; then
        printf 'PASS %-34s %s\n' "$name" "$got"
    else
        fail "$name: got '$got', want $want ($(head -c 200 "$K/body" 2>/dev/null))"
    fi
}

log "HTTP through Kong"
head -c 307200 /dev/zero | tr '\0' 'a' >"$K/big-evil"
printf 'EVIL-BODY-MARKER' >>"$K/big-evil"
head -c 307200 /dev/zero | tr '\0' 'b' >>"$K/big-evil"
head -c 614400 /dev/zero | tr '\0' 'c' >"$K/big-ok"
req h2-benign 200 --http2 https://app.example:$P_KONG/hello
req h1-benign 200 --http1.1 https://app.example:$P_KONG/hello
req h2-uri-attack 403 --http2 --path-as-is "https://app.example:$P_KONG/cgi-bin/../etc/passwd"
req h1-uri-attack 403 --http1.1 --path-as-is "https://app.example:$P_KONG/cgi-bin/../etc/passwd"
req h2-small-body-attack 403 --http2 -d 'a=EVIL-BODY-MARKER' https://app.example:$P_KONG/upload
req h1-large-body-attack 403 --http1.1 --data-binary @"$K/big-evil" https://app.example:$P_KONG/upload
req h2-large-body-benign 200 --http2 --data-binary @"$K/big-ok" https://app.example:$P_KONG/upload
req reject-user-agent 403 --http2 -A reject-me https://app.example:$P_KONG/
req response-detect-mode 200 --http2 https://app.example:$P_KONG/leak
req response-prevent-mode 403 --http2 https://strict.example:$P_KONG/leak
req response-prevent-benign 200 --http1.1 https://strict.example:$P_KONG/hello
req untapped-route 200 --http2 --path-as-is "https://plain.example:$P_KONG/cgi-bin/../etc/passwd"
hdrs="$(curl -sk -D - -o /dev/null --resolve app.example:$P_KONG:$LISTEN "https://app.example:$P_KONG/etc/passwd")"
grep -qi '^x-suritap-cid: [0-9]' <<<"$hdrs" && echo "PASS blocked responses carry X-Suritap-Cid" || fail "X-Suritap-Cid missing"
hdrs="$(curl -sk -D - -o /dev/null --resolve strict.example:$P_KONG:$LISTEN "https://strict.example:$P_KONG/leak")"
if grep -qi '^set-cookie' <<<"$hdrs"; then fail "blocked response kept upstream headers"; else echo "PASS blocked response dropped upstream headers"; fi

stats="$(curl -s http://127.0.0.1:$P_HTTP/__stats)"
echo "backend hits: $stats"
python3 - "$stats" <<'EOF' || fail "blocked requests reached the backend"
import json, sys
hits = json.loads(sys.argv[1])
# Kong buffers request bodies: no blocked request reached the backend.
assert hits.get("/etc/passwd") == 1, hits  # untapped route only
assert hits.get("/") is None, hits         # reject-me
assert hits.get("/upload") == 1, hits      # the benign large body
print("PASS blocked requests did not reach the backend")
EOF

sleep 1
log "EVE"
python3 - "$EVE" <<'EOF' || fail "EVE checks"
import json, sys
alerts = [json.loads(l) for l in open(sys.argv[1]) if '"event_type":"alert"' in l]
def find(sid, **kw):
    for a in alerts:
        st = a.get("suritap", {})
        if a["alert"]["signature_id"] == sid and all(st.get(k) == v for k, v in kw.items()):
            return a
print("alert sids:", sorted({a["alert"]["signature_id"] for a in alerts}))
a = find(9000001, proxy="kong", endpoint="websecure", sni="app.example", alpn="h2", proto="HTTP/2.0", route="app")
assert a, "h2 URI attack alert with Kong metadata"
print("PASS", {k: a["suritap"].get(k) for k in ("proxy", "endpoint", "sni", "alpn", "proto", "route", "service")},
      a["src_ip"], "->", a["dest_ip"], a["dest_port"])
assert find(9000001, proto="HTTP/1.1"), "h1 alert"
assert find(9000002), "body alert"
assert find(9000006, endpoint="websecure"), "response alert in detect mode"
assert find(9000006, endpoint="strict"), "response alert in prevent mode"
print("PASS alerts for URI, body and response (detect+prevent)")
EOF

if [[ "$BENCH" == 1 ]]; then
    log "benchmark: Kong without suritap vs prevent mode (GET, 16 clients)"
    for proto in "" -http1; do
        for host in plain app strict; do
            echo "-- $host ${proto:--http2}"
            "$PROBE" httpbench -url "https://$host.example:$P_KONG/hello" -connect "$LISTEN:$P_KONG" -c 16 -n 20000 $proto
        done
    done
fi

log "fail policy (Suricata stopped)"
stop main
sleep 1
req fail-open-route 200 --http2 https://app.example:$P_KONG/hello
req fail-closed-route 503 --http2 https://strict.example:$P_KONG/hello

log "summary"
docker logs "$CONTAINER" >"$K/kong.log" 2>&1 || true
grep -c "suritap: blocked" "$K/kong.log" | xargs echo "Kong block log lines:"
if grep -E "\[(error|crit|alert)\]" "$K/kong.log" | grep -v "cannot reach Suricata\|connect() to unix:" | grep -q .; then
    grep -E "\[(error|crit|alert)\]" "$K/kong.log" | grep -v "cannot reach Suricata\|connect() to unix:" | head -5
    fail "errors in the Kong log"
fi
if [[ "$FAILED" -gt 0 ]]; then
    echo "$FAILED failure(s)"
    exit 1
fi
echo "ALL PASSED"
