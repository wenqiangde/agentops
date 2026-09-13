#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for platform in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do
  printf '%064d  agentops-v1.2.3-%s\n' 0 "$platform" >> "$TMP/checksums.txt"
done

"$ROOT/scripts/generate-homebrew-formula.sh" \
  --version v1.2.3 \
  --checksums "$TMP/checksums.txt" \
  --out "$TMP/agentops.rb"

grep -q '^class Agentops < Formula' "$TMP/agentops.rb"
grep -q 'github.com/wenqiangde/agentops/releases/download/v1.2.3' "$TMP/agentops.rb"
grep -q 'agentops-v1.2.3-darwin-arm64' "$TMP/agentops.rb"
grep -q 'bin.install.*=> "agentops"' "$TMP/agentops.rb"
ruby -c "$TMP/agentops.rb" >/dev/null
