#!/bin/sh
# Public release installer. Review this script before executing it.
# No root, GitHub login, project execution or automatic prerequisite installation.
set -eu
umask 077
SCAN_VERSION=v0.7.0-alpha.2
SCAN_REPO=awarelyeu/awarely-sbom-scanner
SCAN_DEST="${HOME:?HOME is required}/.local/bin/awarely-scan"
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo 'STOP: only Linux amd64 and arm64 are supported.' >&2; exit 2 ;;
esac
[ "$(uname -s)" = Linux ] || { echo 'STOP: run this installer on Linux.' >&2; exit 2; }
for SCAN_TOOL in curl tar sha256sum awk gh mktemp; do
  if ! command -v "$SCAN_TOOL" >/dev/null 2>&1; then
    printf 'STOP: missing %s. Install the prerequisites for your distribution:\n' "$SCAN_TOOL" >&2
    echo 'https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md#prerequisites' >&2
    echo 'curl downloads; tar extracts; coreutils provides checksums; gh verifies signed provenance. No GitHub account is needed.' >&2
    exit 2
  fi
done
if ! gh attestation verify --help >/dev/null 2>&1; then
  echo 'STOP: update GitHub CLI from https://cli.github.com before continuing. No login is needed.' >&2
  exit 2
fi
if [ -e "$SCAN_DEST" ] || [ -L "$SCAN_DEST" ]; then
  echo 'STOP: ~/.local/bin/awarely-scan already exists. Keep it for rollback or move it before installing this version.' >&2
  exit 2
fi
SCAN_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/awarely-install.XXXXXXXX")
trap 'rm -rf "$SCAN_TEMP"' EXIT HUP INT TERM
cd "$SCAN_TEMP"
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_URL="https://github.com/$SCAN_REPO/releases/download/$SCAN_VERSION"
for SCAN_FILE in "$SCAN_ARCHIVE" "$SCAN_ARCHIVE.sigstore.jsonl" SHA256SUMS; do
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 -fsSL "$SCAN_URL/$SCAN_FILE" -o "$SCAN_FILE"
done
# Use the public proof, never a user token or an API attestation lookup.
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
GH_CONFIG_DIR="$SCAN_TEMP/gh-config"
export GH_CONFIG_DIR
gh attestation verify "$SCAN_ARCHIVE" --bundle "$SCAN_ARCHIVE.sigstore.jsonl" \
  --repo "$SCAN_REPO" \
  --signer-workflow "$SCAN_REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$SCAN_VERSION"
awk -v file="$SCAN_ARCHIVE" '$2 == file {print; found++} END {if (found != 1) exit 1}' SHA256SUMS > selected.sha256
sha256sum --check selected.sha256
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
./release/awarely-scan version
mkdir -p "$HOME/.local/bin"
# Copy into a private file on the destination filesystem, then publish without
# replacing an existing file or following a destination symlink.
SCAN_STAGE=$(mktemp "$HOME/.local/bin/.awarely-install.XXXXXXXX")
trap 'rm -rf "$SCAN_TEMP"; rm -f "$SCAN_STAGE"' EXIT HUP INT TERM
cat release/awarely-scan > "$SCAN_STAGE"
chmod 700 "$SCAN_STAGE"
ln "$SCAN_STAGE" "$SCAN_DEST"
printf '\nREADY: %s\nStart the guided scanner:\n"%s" guided\n' "$SCAN_DEST" "$SCAN_DEST"
