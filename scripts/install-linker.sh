#!/usr/bin/env bash
# Install a pinned, checksum-verified alternative linker into a private prefix.
#
#   scripts/install-linker.sh mold [PREFIX]
#   scripts/install-linker.sh wild [PREFIX]
#
# PREFIX defaults to ${XDG_DATA_HOME:-$HOME/.local/share}/status-list-server/linkers.
# The linker lands in PREFIX/<tool>-<version>/bin, which is printed on stdout so a
# caller can put it on PATH (CI appends it to $GITHUB_PATH). Nothing outside PREFIX
# is touched: unlike rui314/setup-mold, /usr/bin/ld is never replaced, so a host
# without this step keeps its default linker instead of inheriting a global one.
#
# Versions and digests are pinned here rather than resolved at run time, so a new
# upstream release cannot change what CI links with. Digests were taken from the
# GitHub release assets when the pin was bumped; bump the version and both digests
# together. docs/adr/0003-linux-linker-selection.md records the version policy.
set -euo pipefail

MOLD_VERSION="3.0.0"
MOLD_SHA256_X86_64="6c90d4a474c7c0409dfb575be03a5345878ac14fdba18de8b40fa58c60121189"
MOLD_SHA256_AARCH64="52c759d3689babaea4c42af2f31062a74ab83e17ffb5a8090232534c67b70577"

# Benchmark candidate only; see the ADR for why it is not adopted.
WILD_VERSION="0.10.0"
WILD_SHA256_X86_64="641265506a7c06cfb03181b8916ab663ec8407855db6d4db7f8450667d105283"
WILD_SHA256_AARCH64="e9d670e41f76481a68984f816e25bd2f124664db3ac935053e1a6fc41d2894c2"

tool=${1:?usage: install-linker.sh <mold|wild> [prefix]}
prefix=${2:-${XDG_DATA_HOME:-$HOME/.local/share}/status-list-server/linkers}

[ "$(uname -s)" = Linux ] || { echo "install-linker.sh: $tool is only installed on Linux" >&2; exit 1; }

arch=$(uname -m)
case "$arch" in
    x86_64 | aarch64) ;;
    *) echo "install-linker.sh: no pinned $tool build for $arch" >&2; exit 1 ;;
esac
arch_key=$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]')

case "$tool" in
    mold)
        version=$MOLD_VERSION
        sha_var="MOLD_SHA256_${arch_key}"
        archive="mold-${version}-${arch}-linux"
        url="https://github.com/rui314/mold/releases/download/v${version}/${archive}.tar.gz"
        layout=prefix
        ;;
    wild)
        version=$WILD_VERSION
        sha_var="WILD_SHA256_${arch_key}"
        archive="wild-linker-${version}-${arch}-unknown-linux-gnu"
        url="https://github.com/wild-linker/wild/releases/download/${version}/${archive}.tar.gz"
        layout=flat
        ;;
    *) echo "install-linker.sh: unknown linker '$tool' (expected mold or wild)" >&2; exit 2 ;;
esac
sha256=${!sha_var}
dest="$prefix/$tool-$version"

# Re-running is cheap and never trusts a half-written directory: the marker is
# written last, after the binary has been verified and moved into place.
if [ -f "$dest/.verified-$sha256" ]; then
    echo "$dest/bin"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --retry 3 --output "$work/archive.tar.gz" "$url"
echo "$sha256  $work/archive.tar.gz" | sha256sum --check --quiet - >&2 || {
    echo "install-linker.sh: checksum mismatch for $url" >&2
    exit 1
}
tar -xzf "$work/archive.tar.gz" -C "$work"

rm -rf "$dest"
mkdir -p "$prefix"
if [ "$layout" = prefix ]; then
    mv "$work/$archive" "$dest"
else
    mkdir -p "$dest/bin"
    mv "$work/$archive/wild" "$dest/bin/wild"
fi
"$dest/bin/$tool" --version >&2
touch "$dest/.verified-$sha256"
echo "$dest/bin"
