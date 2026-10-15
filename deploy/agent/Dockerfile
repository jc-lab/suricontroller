# syntax=docker/dockerfile:1
# suri-node-agent image: Suricata (built from source) + the suritap capture
# plugin (built against the same source tree, which it must match exactly)
# + suri-node-agent.
# Build from the repository root:
#   docker build -f deploy/agent/Dockerfile -t suri-node-agent .
ARG SURICATA_VERSION=8.0.7
ARG SURICATA_SHA256=a9d46a9c8f40e81f8a6df3ecc2c5a9a8e8da985876299108d92da547c013ba8c

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
# Replaced module (see go.mod).
COPY adapters/traefik-plugin/go.mod adapters/traefik-plugin/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/jc-lab/suricontroller/pkg/version.Version=${VERSION}" \
    -o /out/suri-node-agent ./cmd/suri-node-agent

# The binary that goes into the image. CI replaces this stage with its prebuilt
# binary (--build-context binary=<dir>) so the image and the release share it.
FROM scratch AS binary
COPY --from=build /out/suri-node-agent /suri-node-agent

FROM alpine:3.24 AS suricata
ARG SURICATA_VERSION SURICATA_SHA256
RUN apk add --no-cache build-base cargo curl file-dev jansson-dev libcap-ng-dev libnet-dev \
    libnetfilter_queue-dev libnfnetlink-dev libpcap-dev linux-headers lz4-dev pcre2-dev rust yaml-dev zlib-dev
WORKDIR /build
RUN curl -fsSLo suricata.tar.gz "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
 && echo "${SURICATA_SHA256}  suricata.tar.gz" | sha256sum -c - \
 && tar -xzf suricata.tar.gz && mv "suricata-${SURICATA_VERSION}" suricata
RUN cd suricata \
 && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-nfqueue --disable-suricata-update \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out \
 && make install-conf DESTDIR=/out \
 && rm -rf /out/var/run   # Alpine's /var/run is a symlink to /run
COPY tap /build/tap
RUN cd tap \
 && SURICATA_SRC=/build/suricata cargo build --release --locked -p suritap-plugin \
 && install -D -m 0755 target/release/libsuritap_plugin.so /out/usr/lib/suricata/suritap.so

FROM alpine:3.24
RUN apk add --no-cache tini nftables iptables ip6tables ca-certificates tzdata \
    jansson libcap-ng libgcc libmagic libnet libnetfilter_queue libnfnetlink libpcap lz4-libs pcre2 yaml zlib
COPY --from=suricata /out/ /
RUN suricata -V \
 && suricata --build-info | grep -q 'NFQ' \
 && test -f /usr/lib/suricata/suritap.so \
 && mkdir -p /usr/share/suri-agent/suricata /etc/suri-agent /var/lib/suri-agent /var/log/suricata /run/suritap \
 && cp -a /etc/suricata/. /usr/share/suri-agent/suricata/ \
 && mkdir -p /etc/suricata/rules.local
COPY deploy/agent/tap.yaml /usr/share/suri-agent/suricata/tap.yaml
COPY --from=binary /suri-node-agent /usr/bin/suri-node-agent
COPY deploy/agent/agent.yaml.example /usr/share/suri-agent/agent.yaml.example
COPY deploy/agent/entrypoint.sh /usr/bin/suri-agent-entrypoint
VOLUME ["/etc/suri-agent", "/etc/suricata", "/var/lib/suri-agent", "/var/log/suricata"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/suri-agent-entrypoint"]
CMD ["run"]
