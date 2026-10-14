#!/usr/bin/env bash
# End-to-end test with real Suricata: runs suri-controller on the host and
# suri-node-agent (docker image) in a privileged container with its own
# network namespace, a veth pair and a peer namespace serving TCP 8080.
#
# Verifies: registration, IDS alerts (af-packet), IPS drops (NFQUEUE via
# nftables), rejected rules (suricata -T), log collection, rollback.
#
# Usage: test/docker/integration.sh [agent-image]   (default suri-node-agent:dev)
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE="${1:-suri-node-agent:dev}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/suri-it.XXXXXX")"
PORT="${PORT:-$((30000 + RANDOM % 20000))}"
API="http://127.0.0.1:$PORT/api/suricontroller.api.v1"
CONTAINER="suri-it-agent-$$"
NODE=docker-01
CTL_PID=""

log() { printf '\033[1;34m[it]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[it] FAIL:\033[0m %s\n' "$*"; exit 1; }
cleanup() {
	set +e
	if [ -n "${KEEP:-}" ]; then log "keeping $WORK and container $CONTAINER"; return; fi
	docker logs "$CONTAINER" > "$WORK/agent.log" 2>&1
	docker rm -f "$CONTAINER" >/dev/null 2>&1
	[ -n "$CTL_PID" ] && kill "$CTL_PID" 2>/dev/null && wait "$CTL_PID" 2>/dev/null
	if [ "${RESULT:-fail}" = ok ]; then
		# The container created root-owned files in the mounted directories.
		docker run --rm -v "$WORK:/w" alpine:3.24 rm -rf /w/agent >/dev/null 2>&1
		rm -rf "$WORK"
	else
		log "logs kept in $WORK"
	fi
}
trap cleanup EXIT

api() { # api Service/Method json
	curl -sS -b "$WORK/cookies" -c "$WORK/cookies" -H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' \
		-X POST "$API.$1" -d "$2"
}
wait_for() { # wait_for description timeout_seconds command...
	local what=$1 timeout=$2; shift 2
	for _ in $(seq "$timeout"); do
		if "$@" >/dev/null 2>&1; then log "ok: $what"; return 0; fi
		sleep 1
	done
	fail "timeout waiting for: $what"
}
b64() { printf '%s' "$1" | base64 -w0; }
commit() { # commit repo path content message
	local base
	base=$(api RepoService/ListCommits "{\"repo\":\"$1\",\"limit\":1}" | jq -r '.head // ""')
	api RepoService/WriteFiles "{\"repo\":\"$1\",\"baseCommit\":\"$base\",\"message\":\"$4\",\"changes\":[{\"path\":\"$2\",\"content\":\"$(b64 "$3")\"}]}"
}
node() { api NodeService/GetNode "{\"id\":\"$NODE\"}"; }
in_sync() { node | jq -e '.node.online and .node.deploy.inSync and .node.deploy.lastStatus == "APPLY_STATUS_SUCCEEDED"'; }
eve_has() { # eve_has substring: searches the eve logs stored by the controller
	local f
	for f in $(api LogService/ListLogFiles "{\"nodeId\":\"$NODE\",\"type\":\"LOG_TYPE_EVE\"}" | jq -r '.files[]?.path'); do
		curl -sS -b "$WORK/cookies" "${API%/suricontroller.api.v1}/logs/download?node=$NODE&path=$f" | grep -q -- "$1" && return 0
	done
	return 1
}
peer_curl() { # peer_curl payload -> exit status of a POST through veth0
	docker exec "$CONTAINER" sh -c "printf 'POST / HTTP/1.0\r\nContent-Length: ${#1}\r\n\r\n$1' | timeout 5 nc -w 3 10.99.0.2 8080 | grep -q pong"
}

log "building controller"
go build -o "$WORK/suri-controller" ./cmd/suri-controller
mkdir -p "$WORK/ctl" "$WORK/agent/etc" "$WORK/agent/suricata" "$WORK/agent/data" "$WORK/agent/log"
SURICONTROLLER_DATA_DIR="$WORK/ctl" SURICONTROLLER_LISTEN="0.0.0.0:$PORT" SURICONTROLLER_ADMIN_PASSWORD=pw \
	SURICONTROLLER_INSECURE_COOKIE=1 SURICONTROLLER_ET_OPEN=false "$WORK/suri-controller" serve > "$WORK/controller.log" 2>&1 &
CTL_PID=$!
wait_for "controller up" 20 curl -sf "http://127.0.0.1:$PORT/healthz"
api AuthService/Login '{"username":"admin","password":"pw"}' | jq -e .principal >/dev/null || fail "login"
# Keep the test offline and fast: no ET Open download.
api RuleService/UpdateProvider '{"name":"et-open","enabled":false}' >/dev/null
HOSTKEY=$(api SystemService/GetInfo '{}' | jq -r .hostKey)

log "preparing agent"
PUBKEY=$(docker run --rm -v "$WORK/agent/etc:/etc/suri-agent" "$IMAGE" keygen -node-id "$NODE" -key-file /etc/suri-agent/agent_ed25519)
api NodeService/AddNode "{\"publicKey\":\"$PUBKEY\"}" | jq -e .node >/dev/null || fail "add node"
cat > "$WORK/agent/etc/agent.yaml" <<EOF
node_id: $NODE
controller:
  url: ws://host.docker.internal:$PORT/agent/v1/connect
  host_key: "$HOSTKEY"
platform:
  profile: systemd-native
  firewall: nftables
interfaces:
  - name: veth0
ips:
  enabled: true
  queues: "0"
logs:
  start_position: beginning
log_level: debug
EOF

log "committing rules"
commit REPO_RULES local/test.rules 'alert tcp any any -> any 8080 (msg:"suritest seen"; flow:to_server; content:"suritest"; sid:9000001; rev:1;)
drop tcp any any -> any 8080 (msg:"blockme dropped"; flow:to_server; content:"blockme"; sid:9000002; rev:1;)
' "test rules" | jq -e .commit >/dev/null || fail "commit rules"
commit REPO_CONFIG common/suricata.yaml 'vars:
  address-groups:
    HOME_NET: "[10.99.0.0/24]"
' "home net" | jq -e .commit >/dev/null || fail "commit config"
# Only the test rules, even if ET Open was downloaded at startup.
commit REPO_CONFIG common/sources.yaml 'providers: [local]
' "sources" | jq -e .commit >/dev/null || fail "commit sources"

log "starting agent container"
docker run -d --name "$CONTAINER" --privileged --add-host host.docker.internal:host-gateway \
	-v "$WORK/agent/etc:/etc/suri-agent" -v "$WORK/agent/suricata:/etc/suricata" \
	-v "$WORK/agent/data:/var/lib/suri-agent" -v "$WORK/agent/log:/var/log/suricata" \
	--entrypoint /bin/sh "$IMAGE" -c '
set -e
apk add -q iproute2 socat >/dev/null
ip netns del peer 2>/dev/null || true
ip netns add peer
ip link del veth0 2>/dev/null || true
ip link add veth0 type veth peer name veth1
ip link set veth1 netns peer
ip addr add 10.99.0.1/24 dev veth0 && ip link set veth0 up
ip netns exec peer ip addr add 10.99.0.2/24 dev veth1
ip netns exec peer ip link set veth1 up
ip netns exec peer ip link set lo up
ethtool -K veth0 tx off rx off gro off tso off >/dev/null 2>&1 || true
ip netns exec peer sh -c "socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:\"cat >/dev/null & echo pong\" &"
exec /sbin/tini -- /usr/bin/suri-agent-entrypoint run' >/dev/null

wait_for "agent online and in sync" 60 in_sync
node | jq -e '.node.engine.version | startswith("8.")' >/dev/null || fail "suricata 8 expected"
node | jq -e '.node.interfaces[0].ipsAllowed' >/dev/null || fail "veth0 should allow IPS"

log "IDS on veth0"
api NodeService/SetInterfaceModes "{\"id\":\"$NODE\",\"modes\":{\"veth0\":\"INTERFACE_MODE_IDS\"}}" >/dev/null
wait_for "IDS applied" 120 sh -c "$(declare -f api node); API='$API'; WORK='$WORK'; NODE='$NODE'; node | jq -e '.node.interfaces[0].appliedMode == \"INTERFACE_MODE_IDS\" and .node.deploy.inSync and (.node.instances|length) == 1 and .node.instances[0].running'"
sleep 2
peer_curl "hello-suritest" || fail "IDS must not block traffic"
peer_curl "blockme-in-ids-mode" || fail "drop rules must not block in IDS mode"
wait_for "IDS alert collected" 60 sh -c "$(declare -f api eve_has); API='$API'; WORK='$WORK'; NODE='$NODE'; eve_has 9000001"

log "IPS on veth0"
api NodeService/SetInterfaceModes "{\"id\":\"$NODE\",\"modes\":{\"veth0\":\"INTERFACE_MODE_IPS\"}}" >/dev/null
wait_for "IPS applied" 120 sh -c "$(declare -f api node); API='$API'; WORK='$WORK'; NODE='$NODE'; node | jq -e '.node.interfaces[0].appliedMode == \"INTERFACE_MODE_IPS\" and .node.deploy.inSync and .node.instances[0].name == \"ips\" and .node.instances[0].running'"
docker exec "$CONTAINER" nft list table inet suricontroller | grep -q 'queue' || fail "nftables steering missing"
sleep 2
peer_curl "normal-request" || fail "IPS must pass normal traffic"
if peer_curl "please-blockme-now"; then fail "IPS did not drop the blockme request"; fi
log "ok: blockme request dropped"
wait_for "IPS drop collected" 60 sh -c "$(declare -f api eve_has); API='$API'; WORK='$WORK'; NODE='$NODE'; eve_has 9000002"

log "invalid rule is rejected by suricata -T"
commit REPO_RULES local/bad.rules 'alert tcp any any -> any any (msg:"bad"; nosuchkeyword:1; sid:9000003; rev:1;)
' "bad rule" >/dev/null
wait_for "validation failure reported" 120 sh -c "$(declare -f api node); API='$API'; WORK='$WORK'; NODE='$NODE'; node | jq -e '.node.deploy.lastStatus == \"APPLY_STATUS_FAILED\" and .node.deploy.lastStage == \"APPLY_STAGE_VALIDATE\"'"
api NodeService/ListApplyHistory "{\"id\":\"$NODE\",\"limit\":1}" | jq -e '.entries[0].report.ruleErrors[0].sid == 9000003' >/dev/null || fail "rule error with sid expected"
peer_curl "still-works" || fail "previous configuration must keep running"
if peer_curl "blockme-again"; then fail "previous IPS rules must stay active"; fi
log "ok: previous configuration still active"

log "rollback by pinning the good rules commit"
GOOD=$(api RepoService/ListCommits '{"repo":"REPO_RULES","limit":2}' | jq -r '.commits[1].id')
api DeployService/SetPolicy "{\"kind\":\"DEPLOY_KIND_RULES\",\"mode\":\"DEPLOY_MODE_PINNED\",\"pinnedCommit\":\"$GOOD\"}" >/dev/null
wait_for "pinned commit applied" 120 in_sync
node | jq -e --arg c "$GOOD" '.node.deploy.appliedBundle.rulesCommit == $c' >/dev/null || fail "applied commit"

log "agent restart restores state without the controller"
kill "$CTL_PID"; wait "$CTL_PID" 2>/dev/null || true; CTL_PID=""
docker restart "$CONTAINER" >/dev/null
sleep 8
wait_for "IPS instance restored at boot" 60 docker exec "$CONTAINER" test -S /run/suri-agent/ips/suricata.sock
docker exec "$CONTAINER" nft list table inet suricontroller | grep -q queue || fail "nftables steering not restored"
peer_curl "after-restart" || fail "traffic after restart"
if peer_curl "blockme-after-restart"; then fail "IPS not enforcing after restart"; fi
log "ok: IPS enforcing after restart without the controller"

RESULT=ok
log "ALL PASSED"
