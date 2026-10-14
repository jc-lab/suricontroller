#!/usr/bin/env bash
# suritap phase-2 validation: Traefik (with the suritap patch) in front of a
# real Suricata 8.0.x.
#
#   SURICATA_PREFIX=/opt/suricata SURICATA_SRC=~/src/suricata-8.0.7 test/tap/traefik.sh [--bench]
#
# TRAEFIK  Traefik built by deploy/traefik/build.sh (default bin/traefik-suritap,
#          built when missing)
# WORK     scratch directory (default /tmp/suritap-traefik)
# PORT_BASE  local ports PORT_BASE+43..45 (Traefik), +80/+81 (backend); default 38400
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${SURICATA_PREFIX:?set SURICATA_PREFIX}"
: "${SURICATA_SRC:?set SURICATA_SRC}"
WORK="${WORK:-/tmp/suritap-traefik}"
TRAEFIK="${TRAEFIK:-$ROOT/bin/traefik-suritap}"
BENCH=0
[[ "${1:-}" == "--bench" ]] && BENCH=1
PORT_BASE="${PORT_BASE:-38400}"
P_HTTP=$((PORT_BASE + 80)) P_TCP=$((PORT_BASE + 81))
P_SECURE=$((PORT_BASE + 43)) P_STRICT=$((PORT_BASE + 44)) P_PLAIN=$((PORT_BASE + 45))

# shellcheck source=test/tap/lib.sh
source "$ROOT/test/tap/lib.sh"

log "build"
build_all
[[ -x "$TRAEFIK" ]] || "$ROOT/deploy/traefik/build.sh" "$TRAEFIK"
"$TRAEFIK" version | head -1

log "start Suricata, backend and Traefik"
# Traefik listens on 127.0.0.2 (the "home" listener); clients come from
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

T="$WORK/traefik"
mkdir -p "$T"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/key.pem" -out "$T/cert.pem" -days 2 -subj "/CN=app.example" \
    -addext "subjectAltName=DNS:app.example,DNS:strict.example,DNS:tcp.example" 2>/dev/null
cat >"$T/traefik.yml" <<EOF
entryPoints:
  websecure:
    address: "$LISTEN:$P_SECURE"
    suritap:
      socketDir: $SOCK
      mode: prevent
      timeout: 1s
      maxRequestBody: 65536
  strict:
    address: "$LISTEN:$P_STRICT"
    suritap:
      socketDir: $SOCK
      mode: prevent
      response: prevent
      failPolicy: closed
      timeout: 1s
  plain:
    address: "$LISTEN:$P_PLAIN"
providers:
  file:
    filename: $T/dynamic.yml
log:
  level: INFO
EOF
cat >"$T/dynamic.yml" <<EOF
tls:
  stores:
    default:
      defaultCertificate:
        certFile: $T/cert.pem
        keyFile: $T/key.pem
http:
  routers:
    app:
      rule: "Host(\`app.example\`) || Host(\`strict.example\`)"
      entryPoints: [websecure, strict, plain]
      service: backend
      tls: {}
  services:
    backend:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:$P_HTTP"
tcp:
  routers:
    echo:
      rule: "HostSNI(\`tcp.example\`)"
      entryPoints: [websecure]
      service: echo
      tls: {}
  services:
    echo:
      loadBalancer:
        servers:
          - address: "127.0.0.1:$P_TCP"
EOF
"$TRAEFIK" --configFile="$T/traefik.yml" >"$T/traefik.log" 2>&1 &
TRAEFIK_PID=$!
PIDS+=($TRAEFIK_PID)
CURL=(curl -sk --max-time 10 -o "$T/body" -w '%{http_code} %{http_version}'
    --resolve app.example:$P_SECURE:$LISTEN --resolve strict.example:$P_STRICT:$LISTEN --resolve app.example:$P_PLAIN:$LISTEN)
for _ in $(seq 1 100); do
    [[ "$("${CURL[@]}" https://app.example:$P_PLAIN/ready || true)" == 200* ]] && break
    sleep 0.2
done

# req NAME EXPECTED_STATUS curl-args...
req() {
    local name="$1" want="$2" got
    shift 2
    got="$("${CURL[@]}" "$@" || true)"
    if [[ "${got%% *}" == "$want" ]]; then
        printf 'PASS %-34s %s\n' "$name" "$got"
    else
        fail "$name: got '$got', want $want ($(head -c 200 "$T/body" 2>/dev/null))"
    fi
}

log "HTTP through Traefik"
head -c 307200 /dev/zero | tr '\0' 'a' >"$T/big-evil"
printf 'EVIL-BODY-MARKER' >>"$T/big-evil"
head -c 307200 /dev/zero | tr '\0' 'b' >>"$T/big-evil"
head -c 614400 /dev/zero | tr '\0' 'c' >"$T/big-ok"
req h2-benign 200 --http2 https://app.example:$P_SECURE/hello
req h1-benign 200 --http1.1 https://app.example:$P_SECURE/hello
req h2-uri-attack 403 --http2 --path-as-is "https://app.example:$P_SECURE/cgi-bin/../../etc/passwd"
req h1-uri-attack 403 --http1.1 --path-as-is "https://app.example:$P_SECURE/cgi-bin/../../etc/passwd"
req h2-small-body-attack 403 --http2 -d 'a=EVIL-BODY-MARKER' https://app.example:$P_SECURE/upload
req h1-streamed-body-attack 403 --http1.1 --data-binary @"$T/big-evil" https://app.example:$P_SECURE/upload
req h2-streamed-body-benign 200 --http2 --data-binary @"$T/big-ok" https://app.example:$P_SECURE/upload
req reject-user-agent 403 --http2 -A reject-me https://app.example:$P_SECURE/
req response-detect-mode 200 --http2 https://app.example:$P_SECURE/leak
req response-prevent-mode 403 --http2 https://strict.example:$P_STRICT/leak
req untapped-entrypoint 200 --http2 --path-as-is "https://app.example:$P_PLAIN/cgi-bin/../../etc/passwd"
grep -q 'X-Suritap-Cid\|x-suritap-cid' <(curl -sk -D - -o /dev/null --resolve app.example:$P_SECURE:$LISTEN \
    "https://app.example:$P_SECURE/etc/passwd") && echo "PASS blocked responses carry X-Suritap-Cid" || fail "X-Suritap-Cid missing"

stats="$(curl -s http://127.0.0.1:$P_HTTP/__stats)"
echo "backend hits: $stats"
python3 - "$stats" <<'EOF' || fail "blocked requests reached the backend"
import json, sys
hits = json.loads(sys.argv[1])
# /etc/passwd only via the untapped entry point; small-body attack never arrived;
# the streamed attack was cut off while the backend read it.
assert hits.get("/etc/passwd") == 1, hits
assert hits.get("/") is None, hits  # reject-me
assert hits.get("/upload") == 2, hits
print("PASS blocked requests did not reach the backend")
EOF

log "TCP router terminating TLS"
python3 - "$LISTEN" "$P_SECURE" <<'EOF' || fail "TCP stream tap"
import socket, ssl, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5), server_hostname="tcp.example")
s.sendall(b"hello\n")
echo = s.recv(64)
assert echo == b"hello\n", echo
print("PASS tcp-benign echo", echo)
s.sendall(b"RAW-STREAM-EVIL\n")
try:
    data = s.recv(64)
except (ConnectionError, ssl.SSLError, socket.timeout) as e:
    data = b""
assert data == b"", data
print("PASS tcp-attack connection closed")
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
sids = sorted({a["alert"]["signature_id"] for a in alerts})
print("alert sids:", sids)
a = find(9000001, proxy="traefik", endpoint="websecure", sni="app.example", alpn="h2", proto="HTTP/2.0")
assert a, "h2 URI attack alert with Traefik metadata"
print("PASS", {k: a["suritap"][k] for k in ("proxy", "endpoint", "sni", "alpn", "proto")}, a["src_ip"], "->", a["dest_ip"], a["dest_port"])
assert find(9000001, proto="HTTP/1.1"), "h1 alert"
assert find(9000002), "body alert"
assert find(9000006, endpoint="websecure"), "response alert in detect mode"
assert find(9000006, endpoint="strict"), "response alert in prevent mode"
assert find(9000007, route="echo@file", proto="tcp"), "tcp stream alert"
print("PASS alerts for URI, body, response (detect+prevent) and TCP stream")
EOF

if [[ "$BENCH" == 1 ]]; then
    log "benchmark: Traefik without suritap vs prevent mode (GET, 16 clients)"
    for proto in "" -http1; do
        for ep in plain:$P_PLAIN websecure:$P_SECURE strict:$P_STRICT; do
            name="${ep%%:*}" port="${ep##*:}"
            echo "-- $name ${proto:--http2}"
            "$PROBE" httpbench -url "https://app.example:$port/hello" -connect "$LISTEN:$port" -c 16 -n 20000 $proto
        done
    done
fi

log "fail policy (Suricata stopped)"
stop main
sleep 1
req fail-open-entrypoint 200 --http2 https://app.example:$P_SECURE/hello
req fail-closed-entrypoint 503 --http2 https://strict.example:$P_STRICT/hello

log "summary"
grep -c "suritap: blocked" "$T/traefik.log" | xargs echo "Traefik block log lines:"
if [[ "$FAILED" -gt 0 ]]; then
    echo "$FAILED failure(s)"
    exit 1
fi
echo "ALL PASSED"
