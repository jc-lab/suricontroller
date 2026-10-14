# Shared helpers of the suritap integration scripts (sourced).
# Expects ROOT, WORK, SURICATA_PREFIX and SURICATA_SRC.

SURICATA="$SURICATA_PREFIX/bin/suricata"
SURICATASC="$SURICATA_PREFIX/bin/suricatasc"
PLUGIN="$ROOT/tap/target/release/libsuritap_plugin.so"
PROBE="$ROOT/bin/suritap-probe"
PIDS=()
FAILED=0

log() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*"; FAILED=$((FAILED + 1)); }

cleanup() {
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT

# render NAME [sed expressions...] -> $WORK/NAME/suricata.yaml
render() {
    local name="$1" dir="$WORK/$1" etc="$SURICATA_PREFIX/etc/suricata"
    shift
    rm -rf "$dir"
    mkdir -p "$dir/log" "$dir/run" "$dir/rules"
    cp "$ROOT/test/tap/tap.rules" "$dir/rules/"
    sed -e "s#@DIR@#$dir#g" -e "s#@PLUGIN@#$PLUGIN#" -e "s#@ETC@#$etc#" -e "s#@RULES@#$dir/rules#" \
        "$ROOT/test/tap/suricata-tap.yaml.in" | sed "$@" > "$dir/suricata.yaml"
}

# start NAME WORKERS -> waits until all worker sockets exist
start() {
    local dir="$WORK/$1" last=$(($2 - 1))
    "$SURICATA" -c "$dir/suricata.yaml" --capture-plugin=suritap --pidfile "$dir/run/suricata.pid" -l "$dir/log" \
        >"$dir/log/stdout.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 300); do
        if [[ -S "$dir/run/worker-$last.sock" ]] && grep -qi "engine started" "$dir/log/suricata.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    tail -20 "$dir/log/suricata.log"
    echo "suricata ($1) did not start"
    exit 1
}

stop() {
    local pid
    pid="$(cat "$WORK/$1/run/suricata.pid")"
    kill "$pid"
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
}

reload() {
    local dir="$WORK/$1" n
    n="$(grep -c 'rule reload complete' "$dir/log/suricata.log" || true)"
    "$SURICATASC" -c ruleset-reload-nonblocking "$dir/run/suricata-command.socket" >/dev/null
    for _ in $(seq 1 120); do
        [[ "$(grep -c 'rule reload complete' "$dir/log/suricata.log" || true)" -gt "$n" ]] && return 0
        sleep 0.25
    done
    fail "reload did not complete"
}

# build_all builds the plugin, the Rust tools and the probe.
build_all() {
    (cd "$ROOT/tap" && SURICATA_SRC="$SURICATA_SRC" cargo build --release -p suritap-plugin -p suritap --bins -q)
    (cd "$ROOT" && go build -o "$PROBE" ./cmd/suritap-probe)
    "$SURICATA" -V
}
