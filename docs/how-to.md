# Awarely Scan: complete Linux and application guide

From a verified binary to a local SBOM, an API check or a saved inventory. All application names, paths, IDs and credentials in examples are fictional.

[English](how-to.md) · [Română](how-to.ro.md)

Release: `v0.6.0-alpha.1`

- [1. Choose your workflow](#choose)
- [2. Prepare the Linux machine](#prerequisites)
- [3. Download, verify and run](#install)
- [4. Debian](#debian)
- [4. Ubuntu](#ubuntu)
- [4. Rocky Linux](#rocky-linux)
- [4. AlmaLinux](#almalinux)
- [4. Amazon Linux 2023](#amazon-linux-2023)
- [4. Amazon Linux 2](#amazon-linux-2)
- [5. Choose the collection scope](#scope)
- [6. Collect an application instead](#applications)
- [6b. Java and other ecosystems with optional Syft](#syft)
- [7. Upload the local SBOM in Monitor](#upload)
- [8. Create and protect a machine credential](#credentials)
- [9. Check without saving](#check)
- [10. Synchronize one source](#sync)
- [11. Read findings, exports and alerts](#results)
- [12. Rescan after a package update](#after-remediation)
- [13. Rotate, revoke and retire a source](#credentials-lifecycle)
- [14. Limits and safe retries](#limits)
- [15. Troubleshooting and exit codes](#troubleshooting)

<a id="choose"></a>

## 1. Choose your workflow

| Mode | Account / plan | What happens |
| --- | --- | --- |
| Local file | No account; Apache-2.0 CLI | host/app writes CycloneDX 1.6 JSON locally. No network or CVE evaluation. |
| Upload in Assets | Monitor Pro or active Pro trial | Review the SBOM in the browser, apply changes and Save. |
| API check | Pro access + Check only credential | Returns a local JSON report. Does not save inventory or send alerts. |
| API sync | Pro access + Sync only or Check and sync credential | Immediately replaces only the authorized source in saved inventory. |

The release is an API preview. The same Linux binary supports amd64 and arm64 builds across the distributions below. Jenkins integration, containers, AMI/VHD images, Alpine and arbitrary binary scanning are not available. An offline Linux root directory is supported; an image file is not.

Read steps 2–3 first. Choose one distribution in step 4, then either upload (step 7), check (steps 8–9), or sync (steps 8 and 10). For application manifests, use step 6 instead of step 4.


<a id="prerequisites"></a>

## 2. Prepare the Linux machine

Run steps 2–3 in the same Bash session as your regular Linux user. sudo is only needed to install prerequisites; Awarely Scan needs neither root nor a background service. You need read access to packages/project and write access to your output directory.

First identify the system and available commands. This block only checks: MISSING means you need to install that tool using your distribution block below.

```sh
uname -m
cat /etc/os-release
for tool in curl tar sha256sum awk gh; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'OK: %s\n' "$tool"
  else
    printf 'MISSING: %s\n' "$tool"
  fi
done
if command -v gh >/dev/null 2>&1; then
  gh --version
  gh attestation verify --help
fi
```

| Command / tool | Purpose and what to do if missing |
| --- | --- |
| uname -m | Architecture: x86_64 → amd64; aarch64/arm64 → arm64. No binary is published for other architectures. |
| cat /etc/os-release | Distribution and version: ID and VERSION_ID identify the installation block. If the file is absent, check the image with its administrator instead of guessing. |
| curl + ca-certificates | Download files over HTTPS and validate the server certificate. Install below; do not use curl -k. |
| tar | Extract the verified archive. Install the tar package if missing. |
| sha256sum / coreutils | Verify file integrity. The command is supplied by coreutils, which also provides uname, mktemp and chmod. |
| awk | Select the checksum for your archive. If missing, the distribution block installs gawk. |
| gh attestation verify | Verify build provenance using the publicly downloaded signed bundle. No GitHub account, login or token is required. Missing gh: install below. unknown command/unknown flag: update from the official repository and repeat the check. |

Choose only the block for your distribution. If every tool exists and gh attestation verify --help works, skip straight to step 3. These commands configure the official GitHub CLI repository and install prerequisites; they do not install the scanner or upgrade the whole system.

Debian 12/13 and Ubuntu 22.04/24.04/26.04 — apt. apt-get update refreshes package metadata; install adds or updates the requested packages. The key and signed-by entry let APT verify packages from the GitHub CLI repository.

```sh
(
set -eu
# Refresh package metadata and install download/verification tools.
sudo apt-get update
sudo apt-get install -y ca-certificates curl tar coreutils
command -v awk >/dev/null || sudo apt-get install -y gawk
# Add the signing key for the official GitHub CLI package repository.
GH_KEY_FILE=$(mktemp)
trap 'rm -f "$GH_KEY_FILE"' EXIT
curl --proto '=https' --tlsv1.2 -fL \
  https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  -o "$GH_KEY_FILE"
sudo install -d -m 755 /etc/apt/keyrings
sudo install -m 644 "$GH_KEY_FILE" /etc/apt/keyrings/githubcli-archive-keyring.gpg
rm "$GH_KEY_FILE"
# Configure the source for this machine architecture; its key is scoped to this source.
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' "$(dpkg --print-architecture)" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update
# Install gh or upgrade an older installed version.
sudo apt-get install -y gh
)
```

A message such as “1 upgraded” for gh is normal: the older version was replaced. “0 newly installed” is not an error. Continue if the block finishes successfully, then repeat the gh check below.

Rocky Linux 8/9/10, AlmaLinux 8/9/10 and Amazon Linux 2023 — dnf. Install the tools, add the official GitHub CLI repository with config-manager, then install gh. Check the DNF version and choose only one of the two blocks.

```sh
dnf --version
```

For DNF 4:

```sh
(
set -eu
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils 'dnf-command(config-manager)'
sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo dnf install -y gawk
sudo dnf install -y gh
sudo dnf upgrade -y gh
)
```

For DNF 5, instead of the DNF 4 block:

```sh
(
set -eu
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils dnf5-plugins
sudo dnf config-manager addrepo --from-repofile=https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo dnf install -y gawk
sudo dnf install -y gh
sudo dnf upgrade -y gh
)
```

Amazon Linux 2 — yum. yum-utils provides the repository configuration command; the other tools serve the same purposes. Awarely supports inventory/sync for this distribution; CVE assessment remains unavailable.

```sh
(
set -eu
command -v curl >/dev/null || sudo yum install -y curl
sudo yum install -y ca-certificates tar coreutils yum-utils
sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo yum install -y gawk
sudo yum install -y gh
sudo yum update -y gh
)
```

Now check the version and attestation support. If unknown command persists, inspect command -v gh: an older installation may take precedence in PATH.

```sh
command -v gh
gh --version
gh attestation verify --help
```

Do not run gh auth login or create a GitHub token for this installation. In step 3, gh receives the signed proof through --bundle and verifies it without authentication. Downloading and trust-root updates use the internet; local host/app collection does not. For an offline server, verify on a trusted workstation and securely transfer the verified files.

- [Official GitHub CLI installation](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)
- [Verifying a local proof with --bundle](https://cli.github.com/manual/gh_attestation_verify)


<a id="install"></a>

## 3. Download, verify and run

This pins the published preview release instead of silently downloading a changing latest version. Stop on any download, attestation or checksum failure. The outer checksum list contains both architectures; select only the archive you downloaded. Extraction happens only after verification.

No GitHub account or token. Download the original archive and signed proof from the same public release. The proof is cryptographically verified for the exact archive, Awarely repository, release workflow and selected tag before extraction.

umask 077 and mktemp create a new private directory; SCAN_WORK stores its path. Tools are checked before downloading. GitHub authentication is not required. curl downloads the archive and signed proof, gh --bundle validates provenance for the repository/workflow/tag, awk selects the matching checksum, sha256sum checks integrity, and tar extracts only after verification. version and help confirm that the binary starts. SCAN_BIN is set only if the whole block succeeds.

```sh
SCAN_BIN=
umask 077
SCAN_WORK=$(mktemp -d "$HOME/awarely-scan.XXXXXXXX")
(
set -eu
: "${SCAN_WORK:?Could not create working directory}"
for tool in curl tar sha256sum awk gh; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
done
gh attestation verify --help >/dev/null || { echo 'STOP: update GitHub CLI (step 2).' >&2; exit 1; }
cd "$SCAN_WORK"
SCAN_VERSION=v0.6.0-alpha.1
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_RELEASE="https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/${SCAN_VERSION}"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE" -o "$SCAN_ARCHIVE"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/SHA256SUMS" -o SHA256SUMS
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE.sigstore.jsonl" -o "$SCAN_ARCHIVE.sigstore.jsonl"
gh attestation verify "$SCAN_ARCHIVE" \
  --bundle "$SCAN_ARCHIVE.sigstore.jsonl" \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml \
  --source-ref "refs/tags/$SCAN_VERSION"
awk -v file="$SCAN_ARCHIVE" '$2 == file { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum --check selected-SHA256SUMS
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
"$SCAN_WORK/release/awarely-scan" version
"$SCAN_WORK/release/awarely-scan" help
printf 'Working directory: %s\n' "$SCAN_WORK"
)
SCAN_INSTALL_STATUS=$?
if [ "$SCAN_INSTALL_STATUS" -eq 0 ]; then
  SCAN_BIN="$SCAN_WORK/release/awarely-scan"
  printf 'READY: %s\n' "$SCAN_BIN"
else
  SCAN_BIN=
  printf 'STOP: installation incomplete in %s. Fix the error and rerun all of step 3. Do not scan yet.\n' "$SCAN_WORK" >&2
  (exit "$SCAN_INSTALL_STATUS")
fi
```

Keep SCAN_WORK and SCAN_BIN for the next steps. Each output path must be new: the scanner never overwrites an existing report. Choose a new private directory for the next run. A future release is an explicit download and verification, not an automatic update.

If you open a new terminal later, restore the actual directory printed above: SCAN_WORK=/home/your-user/awarely-scan.YOUR_DIRECTORY and SCAN_BIN="$SCAN_WORK/release/awarely-scan". Replace the example path; do not create a new source just because the terminal session changed.

Continue to step 4 or 6 only after the READY message, version output and help. If STOP appears, do not run host/app/check/sync. After fixing the error, copy ALL of step 3 again: it creates a fresh directory, preserves earlier files and updates the variables. A directory containing only .tar.gz and SHA256SUMS means installation did not reach extraction.


<a id="debian"></a>

## 4. Debian

Supported inventory releases: 12, 13; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name debian-13-web-01 \
  --output "$SCAN_WORK/debian-13-web-01.cdx.json"
```

Official Debian advisories use the installed source-package identity and Debian version ordering, including epochs and distribution revisions. Third-party builds and backports repositories need separate assessment.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/debian-13-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/debian-13-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.receipt.json"
```


<a id="ubuntu"></a>

## 4. Ubuntu

Supported inventory releases: 22.04, 24.04, 26.04 LTS; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name ubuntu-24-04-web-01 \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json"
```

Official Ubuntu data is evaluated using source packages and distribution versions. Some fixes require Ubuntu Pro; Awarely does not determine your entitlement. Unresolved assessments remain review candidates. PPAs and specialized channels are outside this assessment.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.receipt.json"
```


<a id="rocky-linux"></a>

## 4. Rocky Linux

Supported inventory releases: 8, 9, 10; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name rocky-9-web-01 \
  --output "$SCAN_WORK/rocky-9-web-01.cdx.json"
```

Official Rocky errata use exact binary package name, architecture, RPM epoch/version/release and module stream where present. EPEL, third-party vendors and packages absent from the catalog remain unevaluated. Published fixes do not cover every unfixed issue.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/rocky-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/rocky-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.receipt.json"
```


<a id="almalinux"></a>

## 4. AlmaLinux

Supported inventory releases: 8, 9, 10; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name alma-9-web-01 \
  --output "$SCAN_WORK/alma-9-web-01.cdx.json"
```

Official AlmaLinux errata use exact binary package name, architecture, RPM epoch/version/release and module stream where present. A package from another RPM distribution is not treated as AlmaLinux. EPEL and unknown vendors remain unevaluated.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/alma-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/alma-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.receipt.json"
```


<a id="amazon-linux-2023"></a>

## 4. Amazon Linux 2023

Supported inventory releases: 2023; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name al2023-web-01 \
  --output "$SCAN_WORK/al2023-web-01.cdx.json"
```

Official ALAS core-repository advisories are compared with installed RPM versions. NVIDIA, Extras, third-party packages and running livepatch state are outside this assessment. A pinned repository can require selecting a newer release to obtain the reported fixed package.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/al2023-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2023-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.receipt.json"
```


<a id="amazon-linux-2"></a>

## 4. Amazon Linux 2

Supported inventory releases: 2; Linux amd64/arm64. Complete steps 2–3 first. The distribution is detected automatically; there is no --distro flag or separate installer.

```sh
"$SCAN_BIN" host --name al2-legacy-01 \
  --output "$SCAN_WORK/al2-legacy-01.cdx.json"
```

Inventory and synchronization only: the current release does not assess AL2 packages against AL2 CVE advisories. check returns an explicit end-of-life/unevaluated coverage gap. A zero match count is not a clean security result. Use a separately maintained assessment process and plan migration.

For local-only use, stop here or upload this .cdx.json in step 7. For remote use, create and protect credentials using step 8, then choose one command below. Both commands require Check and sync permissions; a Check only token permits only the first. Read the full result using step 11.

Check only (no saved-inventory change):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/al2-legacy-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.check.json"
```

Optional: sync replaces this source in the saved inventory. Run only when that is your intended workflow and your token permits it:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2-legacy-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.receipt.json"
```


<a id="scope"></a>

## 5. Choose the collection scope

The default host profile selects common server software and its installed dependency closure. It does not collect every OS package. For DEB it includes nginx/apache2, OpenSSL, SSH, Node.js, Python, PHP, Java, databases and container runtimes; RPM uses distribution package names such as httpd. Missing optional members of this default profile are acceptable.

```sh
"$SCAN_BIN" host --select 'nginx*,openssl,openssh-server' \
  --name demo-web --output "$SCAN_WORK/selected.cdx.json"

"$SCAN_BIN" host --all-packages \
  --name demo-full --output "$SCAN_WORK/all-packages.cdx.json"

"$SCAN_BIN" host --root /srv/offline-linux-root \
  --name demo-offline --output "$SCAN_WORK/offline.cdx.json"
```

Choose one scope; --select and --all-packages cannot be combined. An unmatched custom selector or unresolved dependency makes collection partial (exit 3). Retry after package-manager activity finishes if the database is changing. Do not edit the live RPM/dpkg database or invent metadata to force a result. Offline roots must already be mounted/readable; the CLI does not mount or unpack images.


<a id="applications"></a>

## 6. Collect an application instead

On any supported Linux host, select the project directory containing npm-shrinkwrap.json or package-lock.json v2/v3. The fallback package.json and requirements.txt are also readable, but always partial. No npm install, pip install or project scripts are executed.

```sh
"$SCAN_BIN" app --path /srv/demo-shop --name demo-shop \
  --output "$SCAN_WORK/demo-shop.cdx.json"
```

Lockfiles include resolved direct/transitive, development and optional entries; they do not prove deployment or installation. Workspace links are not followed. requirements.txt includes declared versions only; includes, URLs and dependency resolution are not followed. Partial files can be reviewed/uploaded or checked, but sync rejects them. pnpm/yarn/poetry lockfiles and automatic monorepo discovery are not supported.

For broader collection using Syft, see step 6b.


<a id="syft"></a>

## 6b. Java and other ecosystems with optional Syft

Syft is a separate Anchore tool under Apache-2.0. Awarely does not download or execute it automatically. Use it for collection beyond the native mode, then import CycloneDX JSON 1.4–1.7. Compatible output from the CycloneDX Maven/Gradle plugins is also accepted. Import does not execute builds, Java code or archives.

| Ecosystem | Inventory / sync | CVE check |
| --- | --- | --- |
| Java / Maven | Yes | Maven versions and full coordinates |
| npm, Python / PyPI | Yes | Comparable ranges; other cases need review |
| .NET / NuGet, Go, PHP / Composer, RubyGems, Rust / Cargo | Yes | Unevaluated in this release |

Complete steps 2–3 first and keep the same Bash session: SCAN_WORK and SCAN_BIN must point to the successful installation. Run the three blocks below in order: A — Cosign, B — Syft, C — Java collection. Downloading and verification require internet, but no GitHub account, token, sudo or PATH changes.

A. Install and verify Cosign. This tool verifies the Syft release signature. Download Cosign 3.1.3 from its official release and compare the binary with the pinned SHA-256 for your architecture before its first execution. Values were checked against the official checksum list; do not replace them to bypass a failure. The hash-verified binary then validates its release’s Sigstore proof. Installation stays in SCAN_WORK, and COSIGN_BIN is set only after success.

- [Cosign 3.1.3 — official release](https://github.com/sigstore/cosign/releases/tag/v3.1.3)
- [Cosign — installation and verification](https://docs.sigstore.dev/cosign/system_config/installation/)

```sh
COSIGN_BIN=
umask 077
COSIGN_DIR=$(mktemp -d "${SCAN_WORK:?STOP: complete step 3 first}/cosign-3.1.3.XXXXXXXX")
(
  set -eu
  : "${COSIGN_DIR:?STOP: could not create the Cosign directory}"
  for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
  done
  COSIGN_VERSION=3.1.3
  case "$(uname -m)" in
    x86_64) COSIGN_ARCH=amd64; COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    aarch64|arm64) COSIGN_ARCH=arm64; COSIGN_SHA256=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) echo 'STOP: unsupported architecture' >&2; exit 1 ;;
  esac
  cd "$COSIGN_DIR"
  BASE="https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION"
  curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "$BASE/cosign-linux-$COSIGN_ARCH" -o cosign
  printf '%s  cosign\n' "$COSIGN_SHA256" > selected.sha256
  sha256sum --check selected.sha256
  chmod 700 cosign
  curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "$BASE/cosign-linux-$COSIGN_ARCH.sigstore.json" -o cosign.sigstore.json
  ./cosign verify-blob cosign --bundle cosign.sigstore.json \
    --certificate-identity keyless@projectsigstore.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com
  ./cosign version
)
COSIGN_INSTALL_STATUS=$?
if [ "$COSIGN_INSTALL_STATUS" -eq 0 ]; then
  COSIGN_BIN="$COSIGN_DIR/cosign"
  printf 'READY: %s\n' "$COSIGN_BIN"
else
  COSIGN_BIN=
  echo 'STOP: Cosign installation incomplete. Fix the error and rerun this entire block.' >&2
  (exit "$COSIGN_INSTALL_STATUS")
fi
```

Continue only after successful verification, version v3.1.3 and READY. A bare cosign command does not need to work: this guide invokes its full path through COSIGN_BIN.

B. Install and verify Syft 1.54.0. Use Cosign from block A to verify Anchore’s signed checksum list, then verify the archive before extraction. If Cosign is missing, the block stops before downloads. SYFT_BIN is set only after verification and successful startup.

- [Syft — release verification](https://oss.anchore.com/docs/installation/verification/)

```sh
SYFT_BIN=
umask 077
SYFT_DIR=$(mktemp -d "${SCAN_WORK:?STOP: complete step 3 first}/syft-1.54.0.XXXXXXXX")
(
  set -eu
  : "${SYFT_DIR:?STOP: could not create the Syft directory}"
  test -n "${COSIGN_BIN:-}" && test -x "$COSIGN_BIN" || { echo 'STOP: complete the Cosign block above first.' >&2; exit 1; }
  for tool in curl tar sha256sum awk; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
  done
  SYFT_VERSION=1.54.0
  case "$(uname -m)" in
    x86_64) SYFT_ARCH=amd64 ;;
    aarch64|arm64) SYFT_ARCH=arm64 ;;
    *) echo 'STOP: unsupported architecture' >&2; exit 1 ;;
  esac
  cd "$SYFT_DIR"
  BASE="https://github.com/anchore/syft/releases/download/v$SYFT_VERSION"
  ARCHIVE="syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz"
  CHECKSUMS="syft_${SYFT_VERSION}_checksums.txt"
  for FILE in "$ARCHIVE" "$CHECKSUMS" "$CHECKSUMS.sigstore.json"; do
    curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 "$BASE/$FILE" -o "$FILE"
  done
  "$COSIGN_BIN" verify-blob "$CHECKSUMS" --bundle "$CHECKSUMS.sigstore.json" \
    --certificate-identity 'https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
  awk -v file="$ARCHIVE" '$2 == file {print; count++} END {if (count != 1) exit 1}' "$CHECKSUMS" > selected.sha256
  sha256sum --check selected.sha256
  tar -xzf "$ARCHIVE" syft
  chmod 700 syft
  ./syft version
)
SYFT_INSTALL_STATUS=$?
if [ "$SYFT_INSTALL_STATUS" -eq 0 ]; then
  SYFT_BIN="$SYFT_DIR/syft"
  printf 'READY: %s\n' "$SYFT_BIN"
else
  SYFT_BIN=
  echo 'STOP: Syft installation incomplete. Fix the error and rerun this entire block. Do not scan yet.' >&2
  (exit "$SYFT_INSTALL_STATUS")
fi
```

Continue only after version 1.54.0 and READY. For cosign: command not found or syft: No such file or directory from older instructions, run block A first, then the updated block B. Each run uses a fresh private directory; earlier downloads are neither deleted nor overwritten. SCAN_WORK, SCAN_BIN and existing SBOMs remain unchanged. In a new terminal, restore SCAN_WORK and SCAN_BIN as described in step 3, then COSIGN_BIN and SYFT_BIN using the READY paths shown here, or repeat blocks A–B.

C. Collect the Java application and import the result into Awarely. Start only after both READY messages.

Java example: /srv/demo-java contains the application JAR/WAR artifacts or gradle.lockfile after the build. Select the artifacts actually delivered. A lone pom.xml may inherit versions and does not represent the entire resolved dependency tree. For Maven projects without artifacts, generate the SBOM in your trusted build using the CycloneDX plugin, then use import directly.

```sh
# Select only the application directory you intend to inventory.
# Keep configuration and output outside that directory.
cat > "$SCAN_WORK/syft-config.yaml" <<'YAML'
check-for-app-update: false
enrich: []
java:
  use-network: false
  use-maven-local-repository: false
golang:
  use-packages-lib: false
  search-remote-licenses: false
javascript:
  search-remote-licenses: false
python:
  search-remote-licenses: false
cpp:
  vcpkg-allow-git-clone: false
YAML
"$SYFT_BIN" scan dir:/srv/demo-java --config "$SCAN_WORK/syft-config.yaml" \
  --source-name demo-java --source-version demo \
  --override-default-catalogers java-archive-cataloger,java-gradle-lockfile-cataloger \
  -o "cyclonedx-json=$SCAN_WORK/demo-java.syft.json"
"$SCAN_BIN" import --input "$SCAN_WORK/demo-java.syft.json" \
  --name demo-java --output "$SCAN_WORK/demo-java.cdx.json"
```

demo-java.cdx.json is the normalized local export: upload it in Assets using step 7 or use it below. Keep independently maintained applications/snapshots in separate sources. This configuration disables network enrichment and Go tooling execution; run Syft without root against an explicit directory. For untrusted inputs, use an isolated environment with resource limits. Do not scan /, credential directories or machine-wide caches.

```sh
# Optional check: use the credential downloaded in step 8.
"$SCAN_BIN" check --input "$SCAN_WORK/demo-java.cdx.json" \
  --credentials "$SCAN_WORK/credentials.json" --output "$SCAN_WORK/demo-java-check.json"
# Optional source replacement: requires inventory:write and complete input.
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-java.cdx.json" \
  --credentials "$SCAN_WORK/credentials.json" --output "$SCAN_WORK/demo-java-receipt.json"
```

For other applications, change the target directory and cataloger selection using Syft documentation. Only the eight ecosystems in the table are imported; missing identities, unknown versions or unsupported variants produce exit 3 and a partial inventory that cannot replace a source with sync. File components are intentionally excluded. Maven classifiers and unknown qualifiers are not silently discarded. Repeated components are deduplicated. Awarely does not forward local paths, URLs or arbitrary SBOM metadata.

Complete coverage means the supported software components in the selected file were processed, not that the producer found every dependency or that packages are installed. Import does not authenticate the SBOM producer. The report’s coverage.unevaluated and per-match precision explain assessment limits. No matches for an unevaluated ecosystem is not a clean bill of health.

- [Syft catalogers](https://oss.anchore.com/docs/guides/sbom/catalogers/)
- [CycloneDX Maven](https://cyclonedx.github.io/cyclonedx-maven-plugin/)
- [CycloneDX Gradle](https://github.com/CycloneDX/cyclonedx-gradle-plugin)


<a id="upload"></a>

## 7. Upload the local SBOM in Monitor

1. Create a Monitor account, accept the displayed terms, confirm the emailed code and sign in. An active Pro trial or Pro subscription is needed for Assets. Local collection remains usable without an account.
2. Open Settings → Assets. Choose Import from file and select your generated .cdx.json. Transfer it securely from the server to your workstation first if needed. Do not upload your credentials file.
3. Choose or create an application, for example demo-shop. Review the parsed components, coverage warnings and change preview. Choose replacement only when the file represents the intended application scope; merge keeps existing entries.
4. Apply the preview, then click Save under Your assets. Parsing happens in your browser; Save sends the normalized inventory to Monitor. Shared component identities count once while application associations are retained.
5. Refresh and verify the application/component counts. Generate the complete inventory check and download all PDF/CSV parts or the ZIP archives. API-managed sources retain their own memberships; a manual import does not replace an API source.
6. A Monitor backup is an organization restore, not an ordinary single-application import. Review its broader replacement scope separately.


<a id="credentials"></a>

## 8. Create and protect a machine credential

1. Use an organization manager account with Pro access. Complete the MFA requirements shown by the app. For a password account, enable MFA in Settings → Privacy and sign in with MFA before managing tokens.
2. Open Settings → Assets → Awarely Scan CLI. This is a separate machine credential, not the general CVE API key from API Access.
3. Select New source. Set Token / source label = demo-web-01, Application = demo-shop, Environment = staging. Choose Check only, Sync only, or Check and sync. Choose a short expiry (1–90 days; default 30).
4. Click Create token, then Download secret configuration immediately. The secret is shown/downloadable once and cannot be recovered later. Copy the downloaded file securely to the Linux host, outside your project, at the path below.
5. For a second host or project that must be maintained independently, create a different source. Reusing one source across different hosts makes each sync replace the previous host snapshot. The server binds application/source/environment; changing --name does not change that binding.

Example transfer, run on the workstation that downloaded the configuration. Replace the fictional user, host and directory with your host and the exact SCAN_WORK directory printed on it. Skip the transfer when browser and CLI run on the same machine; move the downloaded file into SCAN_WORK instead.

```sh
scp ./awarely-credentials.json \
  demo-user@demo-host.example.invalid:/home/demo-user/awarely-scan.REPLACE/awarely-credentials.json
```

```sh
chmod 600 "$SCAN_WORK/awarely-credentials.json"
ls -l "$SCAN_WORK/awarely-credentials.json"
```

The file must be a regular file owned by the account running the CLI, with no group/other permissions. Do not commit it, put the token in command arguments, echo it into logs or paste it into an SBOM. Keep the API origin supplied by Monitor; do not substitute a marketing URL.

Illustration only: this intentionally invalid configuration is not usable. All API addresses and secret values below are dummy placeholders. Use the downloaded configuration for real operations.

```json
{
  "schemaVersion": 1,
  "apiUrl": "https://scanner-api.example.invalid",
  "token": "DUMMY_TOKEN_NOT_VALID",
  "applicationId": "DUMMY_APPLICATION_ID",
  "sourceId": "DUMMY_SOURCE_ID"
}
```


<a id="check"></a>

## 9. Check without saving

Use a Check only or Check and sync credential. Replace demo-shop.cdx.json with the file from your distribution section when scanning a host.

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-shop.check.json"
```

Open the resulting JSON with a local viewer. summary gives totals; matches includes advisory IDs and affected component indexes, versions, precision and distribution evidence. coverage explains what was assessed or left unevaluated. Exit 0 means the request succeeded, even when matches exist. No inventory change or email is triggered. There is no automatic CI vulnerability-failure policy in this release.


<a id="sync"></a>

## 10. Synchronize one source

Use Sync only or Check and sync. The snapshot must be complete for the selected inputs. check does not run automatically as part of sync.

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-shop.receipt.json"
```

1. Read the receipt for status, source ID, application ID, revision and source component count.
2. Reload Settings → Assets. The source is already saved: no additional Save click is required for the API update.
3. A later sync replaces that source. Other sources and manual-import associations remain. The same identity/version shared by applications counts once; different versions or distribution identities remain distinct.
4. Run the complete check in Assets to produce the web report and downloadable evidence. A previous report is a snapshot; regenerate it after inventory changes.


<a id="results"></a>

## 11. Read findings, exports and alerts

1. Version-confirmed means the declared/installed version matches a comparable advisory range. It is not proof that exploitation is possible in your deployment. Product-level matches need review.
2. Unevaluated means the service did not assess that component. It never means unaffected. Inspect missing versions, unsupported distributions/vendors/channels, absent catalog entries and AL2 notices.
3. Supported Linux packages use official distribution advisories without a twelve-month publication cutoff. Application dependencies use the stated preceding twelve-month advisory window. Distinct CVE/GHSA identifiers are not guaranteed to be merged aliases.
4. In Assets, generate the complete inventory check. The list is a preview; PDF and CSV include all matches, with versions and application associations. Download every part. ZIP adds JSON, saved inventory and a verification manifest.
5. Configure alert channels, severities and schedules separately in Settings → Alerts. Local collection, check, sync and on-demand reports do not send retrospective alert emails. Saved inventory is used by configured future alerts.
6. A filtered Critical-only alert email and a later full report can have different scopes/times. Review the source, version precision, inventory snapshot and reporting period before comparing counts.


<a id="after-remediation"></a>

## 12. Rescan after a package update

Update packages through your normal distribution or application change-management process. Review the advisory’s fixed distribution version and repository availability; do not replace it with an upstream version guess. On AL2023, check the pinned release. This guide does not automatically upgrade your server.

The complete sequence below requires Check and sync permissions. Keep only the operations you intend to perform; sync changes the saved source.

```sh
"$SCAN_BIN" host --name demo-web \
  --output "$SCAN_WORK/demo-web-after.cdx.json"
"$SCAN_BIN" check --input "$SCAN_WORK/demo-web-after.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-web-after.check.json"
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-web-after.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-web-after.receipt.json"
```

Use the same source credential and collection scope as before. For applications rerun app with the original --path instead of host. Compare findings and unevaluated coverage, refresh Assets and regenerate the report. Package inventory does not verify that a fixed kernel is running or that a service was restarted.


<a id="credentials-lifecycle"></a>

## 13. Rotate, revoke and retire a source

1. Before expiry, create a new credential selecting the existing source in Assets. Download it once, protect it, verify the intended operation, then revoke the old token. Do not create a new source just to rotate a secret.
2. If a token is lost or exposed, revoke it immediately in Assets and create a replacement. Revocation prevents further API access; it does not delete the source inventory.
3. To deliberately empty a source, the API requires a complete empty snapshot and the explicit sync --allow-empty flag. Never use this to work around partial/error output. Do not edit an incomplete SBOM to pretend it is complete.
4. Delete local credential copies after revocation when they are no longer needed. Keep SBOMs and reports according to your organization’s data policy. There is no daemon to uninstall; remove your downloaded binary/work directory when appropriate.


<a id="limits"></a>

## 14. Limits and safe retries

| Boundary | Limit |
| --- | --- |
| API request / cerere API | 5,000 components; 2 MiB normalized JSON |
| Organization inventory / inventar organizație | 5,000 unique identities; 50 applications; 2 MiB combined normalized data |
| Sources / surse | 50 per organization |
| Check / verificare | 6 requests/minute per organization and credential |
| Sync | 30 requests/minute per organization and credential; GET counts |
| Concurrent operations / operații simultane | 2 per organization per operation |
| Check response / răspuns verificare | 5 MiB; 2,000 advisory IDs; 10,000 component matches |
| Credential / token | 1–90 days; 100 active credentials |
| Local output / rezultat local | 5,000 components; 5 MiB |

These scanner budgets are separate from the general CVE API monthly allowance. Other gateway limits can return 429. The CLI does not automatically retry 429 or revision conflict 409. Respect Retry-After; spread scheduled work. Oversized results fail explicitly rather than truncate. A stale/corrupt/unavailable catalog fails instead of returning a clean report.

Sync reads a revision and uses an idempotency key. Bounded transport/503 retries reuse that request. On 409, inspect/recollect before retrying; never blindly overwrite another writer. For controlled automation, --expected-revision and --idempotency-key can be supplied explicitly. A missing local receipt after network/output failure is not proof that the remote write failed; inspect the saved source before repeating. See API documentation for the full contract.


<a id="troubleshooting"></a>

## 15. Troubleshooting and exit codes

| Symptom | Action |
| --- | --- |
| cosign: command not found / syft: No such file or directory | Step 6b: run block A (Cosign), then B (Syft); wait for READY from each. Use COSIGN_BIN and SYFT_BIN rather than assuming tools are on PATH. |
| MISSING / command not found | Return to step 2, install the tool using your distribution block and repeat the check. |
| gh: unknown command / unknown flag | Update GitHub CLI from the official repository (step 2), then check gh --version and gh attestation verify --help. |
| To get started with GitHub CLI / gh auth login | You used the older commands without --bundle. Do not log in: copy the entire updated step-3 block, which downloads the public proof and verifies without an account. |
| release/awarely-scan: No such file or directory / command not found | Installation did not finish or terminal variables were lost. Find and fix the first step-3 error, then rerun the entire block. Do not manually extract to bypass attestation. If installation succeeded earlier, restore SCAN_WORK and SCAN_BIN as described in step 3. |
| Exit 0 | Operation completed; inspect matches and coverage. It is not a no-vulnerabilities status. |
| Exit 2 | Check arguments, file format, supported distribution, credentials ownership/permissions and read access. |
| Exit 3 | Partial local inventory was written. Review warnings; upload/check for review, but do not sync. |
| Exit 4 | Use a new output filename in an owned writable directory. Existing files are preserved. |
| Exit 5 | Interrupted or deadline exceeded. Resolve host/network conditions before retrying. |
| Exit 6 | Remote operation failed. Read the API status/code without logging credentials. |
| HTTP 401 / 403 | Expired/revoked/invalid token, wrong scope or changed entitlement. Recreate the correct credential through Assets. |
| HTTP 409 | Another sync changed the source revision or an idempotency key was reused with different content. Inspect current inventory. |
| HTTP 413 / 422 | Reduce an over-limit scope, or resolve a partial/empty snapshot. Do not split snapshots by repeatedly overwriting one source. |
| HTTP 429 / 503 | Respect retry timing; check service availability. Do not remove safety limits or loop aggressively. |
| No package selected | Check actual package names and selector. --all-packages is an explicit alternative within limits. |
| A different host disappeared | Do not share one source between independent hosts. Give each its own source. |

- [Awarely Scan repository](https://github.com/awarelyeu/awarely-sbom-scanner)
- [API contract and limits](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/api.md)
- [Coverage details](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/coverage.md)
- [Service status](https://monitor.awarely.ro/status)
