# Awarely Scan: complete Linux and application guide

From a verified binary to a local SBOM, an API check or a saved inventory. All application names, paths, IDs and credentials in examples are fictional.

[English](how-to.md) · [Română](how-to.ro.md)

Release: `v0.5.0-alpha.1`

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

1. Use your regular Linux account. Awarely Scan needs neither root nor a background service. You need read access to the package database or the selected project and write access to your output directory.
2. Use uname -m to identify x86_64 (amd64) or aarch64 (arm64). Other binary architectures are not supplied.
3. For downloading and verification, have curl, tar, sha256sum and a current GitHub CLI with gh attestation verify. These preparation tools use the network; local host/app collection does not.
4. If the preparation tools are already installed, skip the installation commands. Otherwise choose only the block for your distribution below. These commands install tools and configure the official GitHub CLI repository, so an administrator/sudo is needed for this one-time preparation, not for scanning.
5. Run the following commands in the same Bash-compatible terminal session. Never run Awarely Scan with sudo. You may verify the archive on a workstation and transfer it securely to an offline host.

```sh
uname -m
cat /etc/os-release
command -v curl tar sha256sum gh
gh attestation verify --help
```

Debian 12/13 and Ubuntu 22.04/24.04/26.04 — apt:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl tar coreutils
(
set -eu
GH_KEY_FILE=$(mktemp)
curl --proto '=https' --tlsv1.2 -fL \
  https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  -o "$GH_KEY_FILE"
sudo install -d -m 755 /etc/apt/keyrings
sudo install -m 644 "$GH_KEY_FILE" /etc/apt/keyrings/githubcli-archive-keyring.gpg
rm "$GH_KEY_FILE"
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' "$(dpkg --print-architecture)" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update
sudo apt-get install -y gh
)
```

Rocky Linux 8/9/10, AlmaLinux 8/9/10 and Amazon Linux 2023 — check dnf --version. For DNF 4 use this block:

```sh
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils 'dnf-command(config-manager)'
sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
sudo dnf install -y gh
```

Only if dnf --version reports DNF 5, use this alternative instead of the DNF 4 block:

```sh
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils dnf5-plugins
sudo dnf config-manager addrepo --from-repofile=https://cli.github.com/packages/rpm/gh-cli.repo
sudo dnf install -y gh
```

Amazon Linux 2 — yum (inventory/sync only; CVE assessment remains unavailable):

```sh
command -v curl >/dev/null || sudo yum install -y curl
sudo yum install -y ca-certificates tar coreutils yum-utils
sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
sudo yum install -y gh
```

If GitHub CLI requests authentication for downloading/verifying public attestations, run gh auth login and follow its browser flow. This is GitHub authentication, separate from Monitor. Never paste an Awarely token into GitHub. On an offline server, do the download/verification on a trusted workstation and securely transfer the verified files.

```sh
gh attestation verify --help
```

- [Official GitHub CLI installation for Debian, Ubuntu and RPM systems](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)


<a id="install"></a>

## 3. Download, verify and run

This pins the published preview release instead of silently downloading a changing latest version. Stop on any download, attestation or checksum failure. The outer checksum list contains both architectures; select only the archive you downloaded. Extraction happens only after verification.

```sh
umask 077
SCAN_WORK=$(mktemp -d "$HOME/awarely-scan.XXXXXXXX")
SCAN_BIN="$SCAN_WORK/release/awarely-scan"
(
set -eu
cd "$SCAN_WORK"
SCAN_VERSION=v0.5.0-alpha.1
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_RELEASE="https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/${SCAN_VERSION}"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE" -o "$SCAN_ARCHIVE"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/SHA256SUMS" -o SHA256SUMS
gh attestation verify "$SCAN_ARCHIVE" \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml \
  --source-ref "refs/tags/$SCAN_VERSION"
awk -v file="$SCAN_ARCHIVE" '$2 == file { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum --check selected-SHA256SUMS
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
"$SCAN_BIN" version
"$SCAN_BIN" help
printf 'Working directory: %s\n' "$SCAN_WORK"
)
```

Keep SCAN_WORK and SCAN_BIN for the next steps. Each output path must be new: the scanner never overwrites an existing report. Choose a new private directory for the next run. A future release is an explicit download and verification, not an automatic update.

If you open a new terminal later, restore the actual directory printed above: SCAN_WORK=/home/your-user/awarely-scan.YOUR_DIRECTORY and SCAN_BIN="$SCAN_WORK/release/awarely-scan". Replace the example path; do not create a new source just because the terminal session changed.


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
