#!/bin/sh
# Regenerates golden outputs by running the real suricata-update (tested
# with 1.3.0) offline, without root and without touching system
# directories or the network.
#
#   testdata/gen-golden.sh              fixture cases: testdata/rules + testdata/cases/*/*.conf
#                                       -> testdata/cases/*/{suricata.rules,stats.txt,datasets.txt}
#   testdata/gen-golden.sh --et DIR     ET Open comparison: DIR/emerging.rules.tar.gz + testdata/et-cases/*/*.conf
#                                       -> DIR/golden/*/{suricata.rules,stats.txt,datasets.txt}
#                                       (then run: RULESET_ET_DIR=DIR go test ./pkg/ruleset/ -run ET)
#
# The rule files are packed in a tarball under "rules/" and planted in
# suricata-update's download cache for a fake file:// URL, so --offline
# loads them exactly like a downloaded ruleset (rule groups are
# "rules/<file>").
set -eu

here=$(cd "$(dirname "$0")" && pwd)
SURICATA_UPDATE=${SURICATA_UPDATE:-suricata-update}
URL=file:///suricontroller-ruleset-golden/rules.tar.gz

work=$(mktemp -d "${TMPDIR:-/tmp}/ruleset-golden.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

# A fake suricata binary keeps suricata-update away from the local Suricata
# installation (build info, suricata.yaml, distribution rules, default
# conf file locations).
cat >"$work/suricata" <<'EOF'
#!/bin/sh
echo "This is Suricata version 7.0.3 RELEASE"
EOF
chmod +x "$work/suricata"
# The default "ignore: [*deleted.rules]" is kept since it is not overridden.
printf 'dist-rule-directory: %s/no-dist-rules\n' "$work" >"$work/update.yaml"

# run_case ARCHIVE CONFDIR OUTDIR
run_case() {
	archive=$1 confdir=$2 outdir=$3
	data=$work/data out=$work/out
	rm -rf "$data" "$out"
	mkdir -p "$data/update/cache" "$out"
	md5=$(printf '%s' "$URL" | md5sum | cut -d' ' -f1)
	cp "$archive" "$data/update/cache/$md5-rules.tar.gz"

	set --
	for c in disable enable drop modify; do
		if [ -f "$confdir/$c.conf" ]; then
			set -- "$@" "--$c-conf" "$confdir/$c.conf"
		else
			set -- "$@" "--$c-conf" /dev/null
		fi
	done
	if ! "$SURICATA_UPDATE" -c "$work/update.yaml" -D "$data" -o "$out" \
		--suricata "$work/suricata" --suricata-version 7.0.3 \
		--suricata-conf "$work/no-suricata.yaml" \
		--offline --url "$URL" --no-test --no-reload "$@" >"$work/log" 2>&1; then
		cat "$work/log" >&2
		exit 1
	fi

	mkdir -p "$outdir"
	cp "$out/suricata.rules" "$outdir/suricata.rules"
	{
		sed -n \
			-e 's/.* -- Loaded \([0-9]*\) rules\.$/loaded \1/p' \
			-e 's/.* -- Disabled \([0-9]*\) rules\.$/disabled_by_conf \1/p' \
			-e 's/.* -- Enabled \([0-9]*\) rules\.$/enabled_by_conf \1/p' \
			-e 's/.* -- Modified \([0-9]*\) rules\.$/modified \1/p' \
			-e 's/.* -- Dropped \([0-9]*\) rules\.$/dropped \1/p' \
			-e 's/.* -- Enabled \([0-9]*\) rules for flowbit dependencies\.$/flowbits_enabled \1/p' \
			-e 's/.* -- Writing rules to .*: total: \([0-9]*\); enabled: \([0-9]*\);.*/total \1\nenabled \2/p' \
			"$work/log"
	} >"$outdir/stats.txt"
	if [ -d "$out/datasets" ]; then
		(cd "$out/datasets" && ls | sort) >"$outdir/datasets.txt"
	else
		: >"$outdir/datasets.txt"
	fi
	echo "generated $outdir"
}

if [ "${1:-}" = "--et" ]; then
	etdir=$(cd "${2:?usage: $0 --et DIR}" && pwd)
	for confdir in "$here"/et-cases/*/; do
		name=$(basename "$confdir")
		run_case "$etdir/emerging.rules.tar.gz" "$confdir" "$etdir/golden/$name"
	done
	exit 0
fi

tar -C "$here" -cf "$work/rules.tar" rules
for confdir in "$here"/cases/*/; do
	run_case "$work/rules.tar" "$confdir" "$confdir"
done
