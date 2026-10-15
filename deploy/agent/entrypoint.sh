#!/bin/sh
# Seeds empty volumes with defaults, then runs suri-node-agent.
set -e
if [ ! -f /etc/suricata/suricata.yaml ]; then
	cp -a /usr/share/suri-agent/suricata/. /etc/suricata/
fi
mkdir -p /etc/suricata/rules.local
# Settings of the suritap instance (agent.yaml tap.config), seeded once.
if [ ! -f /etc/suricata/tap.yaml ]; then
	cp /usr/share/suri-agent/suricata/tap.yaml /etc/suricata/tap.yaml
fi
if [ "$1" = "run" ] && [ ! -f "${SURI_AGENT_CONFIG:-/etc/suri-agent/agent.yaml}" ]; then
	cp /usr/share/suri-agent/agent.yaml.example /etc/suri-agent/agent.yaml.example
	echo "error: ${SURI_AGENT_CONFIG:-/etc/suri-agent/agent.yaml} not found; see /etc/suri-agent/agent.yaml.example" >&2
	exit 1
fi
exec /usr/bin/suri-node-agent "$@"
