#!/usr/bin/env bash
# Generates Go code from proto/ into gen/. Requires protoc in PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="$PWD/bin"
mkdir -p "$BIN"
(cd tools && go build -o "$BIN/" google.golang.org/protobuf/cmd/protoc-gen-go connectrpc.com/connect/cmd/protoc-gen-connect-go)

rm -rf gen
mkdir -p gen
mapfile -t PROTOS < <(find proto -name '*.proto' | sort)
protoc -I proto \
  --plugin=protoc-gen-go="$BIN/protoc-gen-go" \
  --plugin=protoc-gen-connect-go="$BIN/protoc-gen-connect-go" \
  --go_out=gen --go_opt=module=github.com/jc-lab/suricontroller/gen \
  --connect-go_out=gen --connect-go_opt=module=github.com/jc-lab/suricontroller/gen \
  "${PROTOS[@]}"
