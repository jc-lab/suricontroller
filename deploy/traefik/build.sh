#!/usr/bin/env bash
# Builds Traefik with the suritap adapter (adapters/traefik).
#
#   deploy/traefik/build.sh [OUTPUT]          default: bin/traefik-suritap
#
# TRAEFIK_VERSION  Traefik tag with a matching traefik-<tag>.patch (default v3.7.14)
# WORK             where Traefik is cloned (default dist/traefik-build)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="${TRAEFIK_VERSION:-v3.7.14}"
WORK="${WORK:-$ROOT/dist/traefik-build}"
OUT="${1:-$ROOT/bin/traefik-suritap}"
PATCH="$ROOT/deploy/traefik/traefik-$VERSION.patch"
SRC="$WORK/traefik-$VERSION"

[[ -f "$PATCH" ]] || { echo "no patch for Traefik $VERSION ($PATCH)" >&2; exit 1; }
mkdir -p "$WORK" "$(dirname "$OUT")"
if [[ ! -d "$SRC/.git" ]]; then
    git clone -q --depth 1 --branch "$VERSION" https://github.com/traefik/traefik.git "$SRC"
fi
cd "$SRC"
# Start from the pristine tag (this clone is owned by the script).
git reset -q --hard
git clean -fdq
git apply "$PATCH"
go mod edit -require=github.com/jc-lab/suricontroller@v0.0.0 -replace="github.com/jc-lab/suricontroller=$ROOT" \
    -replace="github.com/jc-lab/suricontroller/adapters/traefik-plugin=$ROOT/adapters/traefik-plugin"
go mod tidy
# The dashboard assets are not built; the API and dashboard stay usable
# only with an upstream image. Everything else is unchanged.
CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/traefik/traefik/v3/pkg/version.Version=${VERSION#v}-suritap" \
    -o "$OUT" ./cmd/traefik
echo "built $OUT"
