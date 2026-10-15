VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/jc-lab/suricontroller/pkg/version.Version=$(VERSION)
GO      ?= go

.PHONY: all build controller agent web proto test lint integration docker-agent docker-controller clean tap tap-test tap-integration traefik tap-traefik tap-kong-test tap-kong

all: build

build: controller agent

controller:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/suri-controller ./cmd/suri-controller

agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/suri-node-agent ./cmd/suri-node-agent

# Builds the web UI into web/dist (embedded by the next controller build).
web:
	cd web/ui && npm ci && npm run build

# Regenerates Go (and TypeScript, when the script exists) code from proto/.
proto:
	./scripts/gen-proto.sh
	@if [ -x scripts/gen-proto-ts.sh ]; then ./scripts/gen-proto-ts.sh; fi

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

# Real Suricata end-to-end test (needs docker and the agent image).
integration: docker-agent
	./test/docker/integration.sh suri-node-agent:dev

# suritap: Rust client library + mock server, the Suricata capture plugin
# and the Go probe. The plugin is only built when SURICATA_SRC points to the
# configured source tree of the Suricata it will be loaded into.
tap:
	cd tap && cargo build --release -p suritap --bins
	@if [ -n "$(SURICATA_SRC)" ]; then \
		cd tap && SURICATA_SRC="$(SURICATA_SRC)" cargo build --release -p suritap-plugin; \
	else echo "SURICATA_SRC not set: skipping suritap-plugin"; fi
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/suritap-probe ./cmd/suritap-probe

# Unit tests and Go<->Rust interoperability (no Suricata needed).
tap-test:
	cd tap && cargo test -p suritap
	cd tap && cargo build -p suritap --bins
	$(GO) test -race ./pkg/suritap/ ./adapters/...
	cd adapters/traefik-plugin && $(GO) vet ./... && $(GO) test -race ./...
	# The interpreter itself is racy: no -race for the Yaegi harness.
	cd test/tap/yaegi && $(GO) vet ./... && $(GO) test ./...

# Phase-1 validation against a real Suricata (needs SURICATA_PREFIX and SURICATA_SRC).
tap-integration:
	./test/tap/run.sh

# Patched Traefik build with the shared-memory adapter (deploy/traefik) ->
# bin/traefik-suritap. The plugin (adapters/traefik-plugin) needs no build.
traefik:
	./deploy/traefik/build.sh

# Official Traefik + plugin + real Suricata end-to-end (needs SURICATA_PREFIX
# and SURICATA_SRC); ./test/tap/traefik.sh --patch tests the patched build.
tap-traefik:
	./test/tap/traefik.sh

# Kong plugin (adapters/kong): socket client test with the Kong image's
# OpenResty against suritap-mockd (needs docker and a built mockd).
tap-kong-test:
	./test/tap/kong/transport.sh

# Official Kong image + plugin + real Suricata end-to-end (needs docker,
# SURICATA_PREFIX and SURICATA_SRC).
tap-kong:
	./test/tap/kong.sh

docker-agent:
	docker build -f deploy/agent/Dockerfile --build-arg VERSION=$(VERSION) -t suri-node-agent:dev .

docker-controller:
	docker build -f deploy/controller/Dockerfile --build-arg VERSION=$(VERSION) -t suri-controller:dev .

clean:
	rm -rf bin
