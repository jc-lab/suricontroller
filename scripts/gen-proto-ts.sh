#!/usr/bin/env bash
# Generates TypeScript code (protobuf-es v2 messages + service descriptors)
# from proto/ into web/ui/src/gen/ for suri-controller-web.
#
# Requires protoc in PATH (or $PROTOC) and `npm ci` in web/ui (for
# @bufbuild/protoc-gen-es). The output is committed so that `npm run build`
# does not need protoc.
set -euo pipefail
cd "$(dirname "$0")/.."

PROTOC="${PROTOC:-protoc}"
PLUGIN="$PWD/web/ui/node_modules/.bin/protoc-gen-es"
OUT="$PWD/web/ui/src/gen"

if [ ! -x "$PLUGIN" ]; then
  echo "protoc-gen-es not found; run 'npm ci' in web/ui first" >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
mapfile -t PROTOS < <(find proto -name '*.proto' | sort)
"$PROTOC" -I proto \
  --plugin=protoc-gen-es="$PLUGIN" \
  --es_out="$OUT" \
  --es_opt=target=ts,import_extension=none \
  "${PROTOS[@]}"
echo "generated TypeScript into ${OUT#"$PWD"/}"
