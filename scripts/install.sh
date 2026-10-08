#!/bin/sh
# Public release installer. Review this script before executing it.
# No root, GitHub login, project execution or automatic prerequisite installation.
set -eu
umask 077
SCAN_VERSION=v0.10.0
SCAN_REPO=awarelyeu/awarely-sbom-scanner
SCAN_DEST="${HOME:?HOME is required}/.local/bin/awarely-scan"
# Shell input is never evaluated. Only fixed commands are suggested for the OS.
scan_prerequisite_help() {
  SCAN_DISTRO=
  if [ -r /etc/os-release ]; then
    while IFS= read -r SCAN_LINE; do
      case "$SCAN_LINE" in ID=*) SCAN_DISTRO=${SCAN_LINE#ID=} ;; esac
    done < /etc/os-release
  fi
  echo 'Install the missing tools in another terminal (or ask your administrator):' >&2
  case "$SCAN_DISTRO" in
    ubuntu|debian|\"ubuntu\"|\"debian\")
      echo 'sudo apt-get update && sudo apt-get install -y ca-certificates curl tar gzip coreutils gawk' >&2 ;;
    amzn|rocky|almalinux|\"amzn\"|\"rocky\"|\"almalinux\")
      echo 'sudo dnf install -y ca-certificates tar gzip coreutils gawk' >&2
      echo 'If curl is missing: sudo dnf install -y curl' >&2
      echo 'Amazon Linux 2: replace dnf with yum.' >&2 ;;
    *) echo 'Install curl, ca-certificates, tar, gzip, coreutils and awk using your system package manager.' >&2 ;;
  esac
}
while :; do
  SCAN_MISSING=
  for SCAN_TOOL in curl tar gzip sha256sum awk mktemp uname mkdir chmod cat ln rm; do
    if ! command -v "$SCAN_TOOL" >/dev/null 2>&1; then
      printf 'MISSING: %s\n' "$SCAN_TOOL" >&2
      SCAN_MISSING=yes
    fi
  done
  [ -n "$SCAN_MISSING" ] || break
  scan_prerequisite_help
  printf 'Press Enter to check again, or q to quit: ' >&2
  IFS= read -r SCAN_REPLY || exit 2
  case "$SCAN_REPLY" in q|quit) exit 2 ;; esac
done
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo 'STOP: only Linux amd64 and arm64 are supported.' >&2; exit 2 ;;
esac
[ "$(uname -s)" = Linux ] || { echo 'STOP: run this installer on Linux.' >&2; exit 2; }
SCAN_TEMP=$(mktemp -d "${TMPDIR:-/tmp}/awarely-install.XXXXXXXX")
trap 'rm -rf "$SCAN_TEMP"' EXIT HUP INT TERM
cd "$SCAN_TEMP"
# Keep verification separate from the user's GitHub credentials/configuration.
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
GH_CONFIG_DIR="$SCAN_TEMP/gh-config"
GH_NO_UPDATE_NOTIFIER=1
export GH_CONFIG_DIR GH_NO_UPDATE_NOTIFIER
SCAN_GH=
if command -v gh >/dev/null 2>&1 && gh attestation verify --help >/dev/null 2>&1; then
  SCAN_GH=$(command -v gh)
else
  echo 'GitHub CLI (gh) is missing or too old. It is needed only to verify this installation.'
  echo 'Awarely can temporarily download GitHub CLI 2.102.0 from the official release, verify its pinned SHA-256, and remove it when finished.'
  echo 'No root, package repository, GitHub account or login is needed. The scanner itself does not need gh.'
  printf 'Prepare the temporary verifier (yes/no) [no]: '
  IFS= read -r SCAN_REPLY || exit 2
  [ "$SCAN_REPLY" = yes ] || { echo 'Installation cancelled. No verifier was downloaded.'; exit 2; }
  SCAN_GH_VERSION=2.102.0
  SCAN_GH_PREFIX="gh_${SCAN_GH_VERSION}_linux_${SCAN_ARCH}"
  SCAN_GH_ARCHIVE="$SCAN_GH_PREFIX.tar.gz"
  # Maintainer-verified upstream release pins; no checksum downloaded at install time is trusted for this bootstrap.
  case "$SCAN_ARCH" in
    amd64) SCAN_GH_SHA=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386 ;;
    arm64) SCAN_GH_SHA=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484 ;;
  esac
  curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 --max-redirs 4 --max-filesize 41943040 -fsSL \
    "https://github.com/cli/cli/releases/download/v$SCAN_GH_VERSION/$SCAN_GH_ARCHIVE" -o "$SCAN_GH_ARCHIVE"
  printf '%s  %s\n' "$SCAN_GH_SHA" "$SCAN_GH_ARCHIVE" > verifier.sha256
  sha256sum --check verifier.sha256
  mkdir verifier
  tar -xzf "$SCAN_GH_ARCHIVE" -C verifier "$SCAN_GH_PREFIX/bin/gh" "$SCAN_GH_PREFIX/LICENSE"
  SCAN_GH="$SCAN_TEMP/verifier/$SCAN_GH_PREFIX/bin/gh"
  "$SCAN_GH" attestation verify --help >/dev/null
fi
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_URL="https://github.com/$SCAN_REPO/releases/download/$SCAN_VERSION"
for SCAN_FILE in "$SCAN_ARCHIVE" "$SCAN_ARCHIVE.sigstore.jsonl" SHA256SUMS; do
  curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 --max-redirs 4 --max-filesize 41943040 -fsSL "$SCAN_URL/$SCAN_FILE" -o "$SCAN_FILE"
done
# Use the public proof, never a user token or an API attestation lookup.
"$SCAN_GH" attestation verify "$SCAN_ARCHIVE" --bundle "$SCAN_ARCHIVE.sigstore.jsonl" \
  --repo "$SCAN_REPO" \
  --signer-workflow "$SCAN_REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$SCAN_VERSION" --deny-self-hosted-runners
awk -v file="$SCAN_ARCHIVE" '$2 == file {print; found++} END {if (found != 1) exit 1}' SHA256SUMS > selected.sha256
sha256sum --check selected.sha256
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
./release/awarely-scan version
if [ -e "$SCAN_DEST" ] || [ -L "$SCAN_DEST" ]; then
  # This candidate was authenticated above. It performs a protected atomic
  # upgrade with a rollback backup, after the user's separate confirmation.
  ./release/awarely-scan install
  exit $?
fi
mkdir -p "$HOME/.local/bin"
# Copy into a private file on the destination filesystem, then publish without
# replacing an existing file or following a destination symlink.
SCAN_STAGE=$(mktemp "$HOME/.local/bin/.awarely-install.XXXXXXXX")
trap 'rm -rf "$SCAN_TEMP"; rm -f "$SCAN_STAGE"' EXIT HUP INT TERM
cat release/awarely-scan > "$SCAN_STAGE"
chmod 700 "$SCAN_STAGE"
ln "$SCAN_STAGE" "$SCAN_DEST"
printf '\nREADY: %s\nStart the guided scanner:\n"%s" guided\n' "$SCAN_DEST" "$SCAN_DEST"
