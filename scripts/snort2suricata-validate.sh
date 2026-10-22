#!/bin/sh
# Downloads the Snort community rulesets (Snort 2.9 and Snort 3), converts
# them with snort2suricata and checks that Suricata loads the result.
#
#   scripts/snort2suricata-validate.sh [workdir]
#
# Suricata runs from $SURICATA when set, otherwise in an alpine container
# (needs docker). Every rule of the Snort 2 file is enabled for the check.
set -eu

work=${1:-$(mktemp -d)}
mkdir -p "$work"
root=$(cd "$(dirname "$0")/.." && pwd)

go build -o "$work/snort2suricata" "$root/cmd/snort2suricata"

fetch() {
	mkdir -p "$work/$1"
	curl -fsSL "https://www.snort.org/downloads/community/$1.tar.gz" | tar xz -C "$work/$1" --strip-components=1
}
fetch community-rules
fetch snort3-community-rules

"$work/snort2suricata" -dialect snort2 -enable-all -o "$work/snort2.rules" \
	-rejected "$work/snort2.rejected" -report "$work/snort2.json" "$work/community-rules/community.rules"
"$work/snort2suricata" -dialect snort3 -o "$work/snort3.rules" \
	-rejected "$work/snort3.rejected" -report "$work/snort3.json" "$work/snort3-community-rules/snort3-community.rules"

# Snort rules use $SIP_SERVERS, which suricata.yaml does not define.
check() {
	if [ -n "${SURICATA:-}" ]; then
		"$SURICATA" -T -S "$1" -l "$work" --set 'vars.address-groups.SIP_SERVERS=$HOME_NET'
	else
		docker run --rm -v "$work:/work" alpine:3.24 sh -c \
			"apk add -q --no-cache suricata && suricata -T -S /work/$(basename "$1") -l /tmp \
			--set 'vars.address-groups.SIP_SERVERS=\$HOME_NET'"
	fi
}
for f in snort2 snort3; do
	echo "== $f"
	if check "$work/$f.rules" >"$work/$f.suricata.log" 2>&1; then
		echo "Suricata loaded $work/$f.rules"
	else
		echo "Suricata failed to load $work/$f.rules"
	fi
	grep -E '^(E|W):' "$work/$f.suricata.log" || true
done
