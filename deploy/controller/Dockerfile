# syntax=docker/dockerfile:1
# suri-controller image (with the built-in web UI).
# Build from the repository root:
#   docker build -f deploy/controller/Dockerfile -t suri-controller .
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/web/ui
COPY web/ui/package.json web/ui/package-lock.json ./
RUN npm ci
COPY web/ui/ ./
COPY proto/ /src/proto/
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
# Replaced module (see go.mod).
COPY adapters/traefik-plugin/go.mod adapters/traefik-plugin/
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/ /src/web/dist/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X github.com/jc-lab/suricontroller/pkg/version.Version=${VERSION}" \
    -o /out/suri-controller ./cmd/suri-controller

# The binary that goes into the image. CI replaces this stage with its prebuilt
# binary (--build-context binary=<dir>) so the image and the release share it.
FROM scratch AS binary
COPY --from=build /out/suri-controller /suri-controller

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata tini && adduser -D -H -u 10001 suri \
 && mkdir -p /var/lib/suricontroller && chown suri /var/lib/suricontroller
COPY --from=binary /suri-controller /usr/bin/suri-controller
USER suri
ENV SURICONTROLLER_DATA_DIR=/var/lib/suricontroller SURICONTROLLER_LISTEN=:8080
VOLUME ["/var/lib/suricontroller"]
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/suri-controller"]
CMD ["serve"]
