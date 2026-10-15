VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/jc-lab/suricontroller/pkg/version.Version=$(VERSION)
GO      ?= go

.PHONY: all build controller agent snort2suricata web proto test lint integration docker-agent docker-controller clean

all: build

build: controller agent

controller:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/suri-controller ./cmd/suri-controller

agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/suri-node-agent ./cmd/suri-node-agent

snort2suricata:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/snort2suricata ./cmd/snort2suricata

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

docker-agent:
	docker build -f deploy/agent/Dockerfile --build-arg VERSION=$(VERSION) -t suri-node-agent:dev .

docker-controller:
	docker build -f deploy/controller/Dockerfile --build-arg VERSION=$(VERSION) -t suri-controller:dev .

clean:
	rm -rf bin
