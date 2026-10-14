# syntax=docker/dockerfile:1
# suri-node-agent image: Suricata (>= 8.0.5) + suri-node-agent.
# Build from the repository root:
#   docker build -f deploy/agent/Dockerfile -t suri-node-agent .
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/jc-lab/suricontroller/pkg/version.Version=${VERSION}" \
    -o /out/suri-node-agent ./cmd/suri-node-agent

FROM alpine:3.24
RUN apk add --no-cache suricata tini nftables iptables ip6tables ca-certificates tzdata \
 && suricata -V \
 && mkdir -p /usr/share/suri-agent/suricata /etc/suri-agent /var/lib/suri-agent /var/log/suricata \
 && cp -a /etc/suricata/. /usr/share/suri-agent/suricata/ \
 && mkdir -p /etc/suricata/rules.local
COPY --from=build /out/suri-node-agent /usr/bin/suri-node-agent
COPY deploy/agent/agent.yaml.example /usr/share/suri-agent/agent.yaml.example
COPY deploy/agent/entrypoint.sh /usr/bin/suri-agent-entrypoint
VOLUME ["/etc/suri-agent", "/etc/suricata", "/var/lib/suri-agent", "/var/log/suricata"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/suri-agent-entrypoint"]
CMD ["run"]
