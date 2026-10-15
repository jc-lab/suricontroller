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

# The binary that goes into the image. CI replaces this stage with its prebuilt
# binary (--build-context binary=<dir>) so the image and the release share it.
FROM scratch AS binary
COPY --from=build /out/suri-node-agent /suri-node-agent

FROM alpine:3.24
# Exact apk version to install (e.g. 8.0.7-r0); empty installs the repo's current
# one. CI pins it so the image tag and the layer cache follow the Suricata release.
ARG SURICATA_VERSION=
RUN apk add --no-cache suricata${SURICATA_VERSION:+=$SURICATA_VERSION} tini nftables iptables ip6tables ca-certificates tzdata \
 && suricata -V \
 && mkdir -p /usr/share/suri-agent/suricata /etc/suri-agent /var/lib/suri-agent /var/log/suricata \
 && cp -a /etc/suricata/. /usr/share/suri-agent/suricata/ \
 && mkdir -p /etc/suricata/rules.local
COPY --from=binary /suri-node-agent /usr/bin/suri-node-agent
COPY deploy/agent/agent.yaml.example /usr/share/suri-agent/agent.yaml.example
COPY deploy/agent/entrypoint.sh /usr/bin/suri-agent-entrypoint
VOLUME ["/etc/suri-agent", "/etc/suricata", "/var/lib/suri-agent", "/var/log/suricata"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/suri-agent-entrypoint"]
CMD ["run"]
