#!/usr/bin/env bash
set -euo pipefail

VERSION=""
CHECKSUMS_FILE=""
ASSET_REPO="wenqiangde/agentops"
HOMEPAGE_REPO="wenqiangde/agentops"
OUT="Formula/agentops.rb"

usage() {
  cat <<'USAGE'
Usage:
  scripts/generate-homebrew-formula.sh --version vX.Y.Z --checksums <checksums.txt> [--repo owner/name] [--homepage-repo owner/name] [--out Formula/agentops.rb]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --checksums) CHECKSUMS_FILE="${2:-}"; shift 2 ;;
    --repo) ASSET_REPO="${2:-}"; shift 2 ;;
    --homepage-repo) HOMEPAGE_REPO="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || { echo "Invalid or missing --version: $VERSION" >&2; exit 1; }
[[ -f "$CHECKSUMS_FILE" ]] || { echo "Missing --checksums file: $CHECKSUMS_FILE" >&2; exit 1; }

asset_sha() {
  local asset="$1"
  awk -v asset="$asset" '$2 == asset || $2 == "bin/" asset { print $1 }' "$CHECKSUMS_FILE"
}

darwin_arm64="agentops-${VERSION}-darwin-arm64"
darwin_amd64="agentops-${VERSION}-darwin-amd64"
linux_arm64="agentops-${VERSION}-linux-arm64"
linux_amd64="agentops-${VERSION}-linux-amd64"

sha_darwin_arm64="$(asset_sha "$darwin_arm64")"
sha_darwin_amd64="$(asset_sha "$darwin_amd64")"
sha_linux_arm64="$(asset_sha "$linux_arm64")"
sha_linux_amd64="$(asset_sha "$linux_amd64")"

for value in sha_darwin_arm64 sha_darwin_amd64 sha_linux_arm64 sha_linux_amd64; do
  [[ -n "${!value}" ]] || { echo "Missing checksum for ${value#sha_}" >&2; exit 1; }
done

mkdir -p "$(dirname "$OUT")"
cat > "$OUT" <<RUBY
class Agentops < Formula
  desc "Service inventory, health, deployment, rollback, and backup operations"
  homepage "https://github.com/${HOMEPAGE_REPO}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/${ASSET_REPO}/releases/download/${VERSION}/${darwin_arm64}"
      sha256 "${sha_darwin_arm64}"
    else
      url "https://github.com/${ASSET_REPO}/releases/download/${VERSION}/${darwin_amd64}"
      sha256 "${sha_darwin_amd64}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/${ASSET_REPO}/releases/download/${VERSION}/${linux_arm64}"
      sha256 "${sha_linux_arm64}"
    else
      url "https://github.com/${ASSET_REPO}/releases/download/${VERSION}/${linux_amd64}"
      sha256 "${sha_linux_amd64}"
    end
  end

  def install
    bin.install Dir["agentops-*"].first => "agentops"
    chmod 0755, bin/"agentops"
  end

  test do
    assert_match "Available Commands:", shell_output("#{bin}/agentops --help")
    assert_match "AgentOps Version", shell_output("#{bin}/agentops version")
  end
end
RUBY

echo "Generated Homebrew formula: $OUT"
