# Awarely Scan — Linux SBOM Generator & Software Inventory

[![CI](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Generate a local **CycloneDX SBOM** from application manifests or a focused selection of installed Debian/Ubuntu/Rocky Linux/AlmaLinux/Amazon Linux packages. Local collection runs without root, package installation, project scripts, telemetry or network access. Explicit `check` and `sync` commands communicate with Awarely Monitor over HTTPS.

Built for [Awarely Monitor](https://monitor.awarely.ro/en), with a standalone local workflow you can inspect and use independently.

**Stable release: v0.10.0 for Linux amd64 and arm64.** Local collection is independent of an account. Remote operations require Awarely Monitor Pro and a scoped machine credential created by an organization manager with MFA. The Jenkins integration is maintained in [jenkins-plugin/](jenkins-plugin/) with separate versions and verified releases.

| Workflow | Available |
| --- | --- |
| Guided Linux / npm / Python / Java setup | Yes, with input checks and optional verified Syft |
| Local SBOM file | Yes |
| CVE check through the Awarely API | Yes, without changing saved inventory |
| Inventory synchronization through the Awarely API | Yes, replaces one configured source |
| Verified CLI updates and local rollback | Yes; Syft follows the tested CLI release |
| Jenkins plugin using the same CLI | [Preview integration and walkthrough](jenkins-plugin/) |

## Complete walkthroughs

Follow the **[English guide](docs/how-to.md)** or **[ghidul în română](docs/how-to.ro.md)** for installation and release verification, account setup, MFA, source credentials, local upload, API check/sync, reports, alerts, updates, token rotation and troubleshooting.

| Distribution | Tested releases | Local inventory / sync | Distribution CVE assessment | Walkthrough |
| --- | --- | --- | --- | --- |
| Debian | 12, 13 | Available | Official Debian data | [EN](docs/how-to.md#debian) · [RO](docs/how-to.ro.md#debian) |
| Ubuntu | 22.04, 24.04, 26.04 LTS | Available | Official Ubuntu data | [EN](docs/how-to.md#ubuntu) · [RO](docs/how-to.ro.md#ubuntu) |
| Rocky Linux | 8, 9, 10 | Available | Official Rocky errata | [EN](docs/how-to.md#rocky-linux) · [RO](docs/how-to.ro.md#rocky-linux) |
| AlmaLinux | 8, 9, 10 | Available | Official AlmaLinux errata | [EN](docs/how-to.md#almalinux) · [RO](docs/how-to.ro.md#almalinux) |
| Amazon Linux 2023 | 2023 | Available | Official ALAS core advisories | [EN](docs/how-to.md#amazon-linux-2023) · [RO](docs/how-to.ro.md#amazon-linux-2023) |
| Amazon Linux 2 | 2 | Available | **Not implemented; explicitly unevaluated** | [EN](docs/how-to.md#amazon-linux-2) · [RO](docs/how-to.ro.md#amazon-linux-2) |

All rows cover Linux amd64/arm64. Assessment is limited to supported package identities and available advisory data; packages outside that coverage remain unevaluated. [Application manifest workflow](docs/how-to.md#applications) applies across these distributions. See [coverage details](docs/coverage.md).


## Optional Syft import and Java

Keep the native Linux/npm/Python collectors, or generate an application SBOM with [Syft](https://github.com/anchore/syft) and import it locally:

```sh
awarely-scan import --input application.syft.json --name demo-app --output application.cdx.json
```

Accepts CycloneDX JSON 1.4–1.7 for Maven, npm, PyPI, NuGet, Go, Composer, RubyGems and Cargo. The normalized file supports local upload, API check and source sync. Java checks preserve full Maven coordinates and Maven version ordering. NuGet/Go/Composer/RubyGems/Cargo currently support inventory and sync; their CVE evaluation is explicitly **unevaluated**. Syft is optional: guided mode can download a pinned, verified version and run it after your approval. No Syft runtime dependency is bundled. Manual import remains available.

Follow the complete verified-installation and Java workflow: [English](docs/how-to.md#syft) · [Română](docs/how-to.ro.md#syft). Unknown identities/variants or missing versions make the import partial; partial snapshots cannot sync. This is selected-file coverage, not proof of deployment completeness.

## Guided quick start

After [verified installation](docs/how-to.md#quick-install), run:

```sh
"$HOME/.local/bin/awarely-scan" guided
```

Choose **Linux, npm, Python, Java, or other application ecosystems**. The scanner checks the selected inputs, explains missing prerequisites and writes a private SBOM. Then choose local-only, API check or API sync. Running the binary without arguments in a terminal opens the same menu. All terminal messages are in English.

- Linux is detected automatically. No package-manager command or root access is needed.
- npm reads a resolved lockfile without Node.js/npm. Optional Syft inspection is also available.
- Python offers requirements.txt (partial) or an existing virtual environment through Syft.
- Java inspects built JAR/WAR/EAR artifacts with Syft; it does not build the application.
- Managed Syft uses a pinned archive, verified on every run, with an isolated environment and fixed offline configuration. No gh/Cosign commands are needed for this step. The initial installer can prepare a temporary, pinned and digest-verified GitHub CLI when gh is missing or too old, then remove it. Signed build provenance is still required; no root, system gh package or GitHub login is needed.
- API requests need your explicitly selected private credential file and confirmation. Check preserves saved inventory; sync replaces only the credential's source. Partial inventories cannot sync.

Correct a mistyped path without restarting. Use `b` to go back and `q` to quit; quoted paths and `~/` are accepted. Option **6** reopens a saved Awarely SBOM for check or sync without scanning again. Terminal colors respect `NO_COLOR` and disappear from redirected output.

Checks save both the complete `check-result.json` and a readable `check-summary.txt`, including matches and unevaluated components. Check retries require confirmation. An uncertain sync is never automatically repeated; inspect the source in Monitor before retrying.

See the complete [English](docs/how-to.md) or [Romanian](docs/how-to.ro.md) walkthrough. Existing commands below remain available for scripts and CI.

## Keep the scanner current

From v0.9.0-alpha.1:

```sh
"$HOME/.local/bin/awarely-scan" update --check
"$HOME/.local/bin/awarely-scan" update
"$HOME/.local/bin/awarely-scan" version --tools
```

Updates require confirmation and verified release provenance. One private backup supports `update --rollback`. Stable installations stay stable; prerelease installations also see newer prereleases. Scanning never triggers an update. Managed **Syft 1.54.1** changes only with a tested Awarely release, and its first use still asks before downloading. No arbitrary Syft version or automatic `latest` is executed.

Upgrading an older CLI? Run the current [simplified installer](docs/how-to.md#quick-install); it can upgrade an existing installation after verification and confirmation. Do not move the old binary aside. See [update and rollback steps](docs/how-to.md#scanner-updates).

## Noninteractive commands

Download a Linux amd64 or arm64 archive from [Releases](https://github.com/awarelyeu/awarely-sbom-scanner/releases). Verify its provenance and checksum using [the release instructions](docs/releases.md) before running it. Source builds are also supported:

```sh
go build -trimpath -o ./dist/awarely-scan ./cmd/awarely-scan
```

Go 1.27.1 is the pinned toolchain. There are no third-party Go modules in the executable.

For an application with an npm lockfile:

```sh
./dist/awarely-scan app \
  --path /srv/my-app \
  --name my-app \
  --output my-app.cdx.json
```

For selected installed server packages and their installed dependency closure:

```sh
./dist/awarely-scan host \
  --select 'nginx*,openssl,openssh-server' \
  --name web-server \
  --output web-server.cdx.json
```

Omit `--select` to use the documented [focused server profile](docs/coverage.md). Use `--all-packages` to explicitly include every installed package instead. `--root` accepts a selected offline supported Linux root filesystem.

The output file is created with owner-only permissions and is never overwritten. Choose a new filename for each snapshot. SBOMs can disclose your software stack; keep them private unless you intend to share them.

## What is collected?

| Input | Meaning of the versions | Coverage |
| --- | --- | --- |
| npm `package-lock.json` / `npm-shrinkwrap.json` v2/v3 | Resolved versions | Includes entries for direct, transitive, development and optional dependencies; does not claim they are installed |
| `package.json` fallback | Declared versions | Partial; ranges remain unknown versions, transitive dependencies unresolved |
| `requirements.txt` | Declared requirements | Partial; does not install packages, resolve dependencies or follow includes/URLs |
| Debian/Ubuntu package database | Installed versions | Selected packages plus Depends/Pre-Depends closure |
| Rocky Linux/AlmaLinux/Amazon Linux RPM database | Installed EVR versions | Selected packages plus installed capability providers; SQLite/WAL and Berkeley DB hash |

Native application collection reads only supported manifests in the directory you choose. It does not recursively discover repositories, inspect `node_modules`, read `.env`, execute scripts or fetch registries. npm shrinkwrap takes precedence over package-lock; package.json is a fallback. Workspace links are not followed and are reported as partial coverage.

Every report includes `awarely:coverage`, the selected scope, input filenames and warning codes. CycloneDX composition is conservatively marked incomplete: successfully parsing the selected files does not prove completeness of the deployed application or host.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Selected inputs processed; **not** a vulnerability verdict |
| 2 | Invalid arguments/input, unsupported target or scan error; no new report |
| 3 | Partial inventory written; inspect its coverage warnings |
| 4 | Output could not be published; existing files preserved |
| 5 | Interrupted or deadline exceeded before publication |
| 6 | API operation failed; no successful report was published |

## Using the file with Awarely Monitor

Application SBOMs can be reviewed and uploaded in **Settings → Assets**. Saving an import changes the selected inventory and can affect its configured alerts. Collection itself has no interaction with your Awarely account.

Host checks use official Debian and Ubuntu advisories, the installed source-package identity and Debian version ordering (including epochs and backported revisions). Supported releases are Debian 12/13 and Ubuntu 22.04/24.04/26.04 LTS on amd64/arm64. The report includes the distribution, source version, fixed version when published, advisory link and assessment evidence. Recollect older host SBOMs to include source metadata.

The same binaries automatically detect Rocky Linux and AlmaLinux 8/9/10. RPM checks use each distribution’s official errata, exact binary package identity, architecture, module stream and RPM epoch/version/release ordering. Installed vendor and source metadata are preserved. Third-party RPM vendors and packages without a comparable advisory are explicitly unevaluated. This checks available published fixes; it is not a complete tracker of every unfixed issue, proof of signature authenticity, or proof that an installed kernel is running.

Amazon Linux 2023 is auto-detected as `amzn` and uses official ALAS core-repository advisories on x86_64/aarch64, including noarch packages. Fixed versions are compared using RPM EVR, independently of other distributions. A pinned repository may require an explicit release upgrade to obtain a fix. Amazon Linux 2 reached end of life on June 30, 2026: local inventory and sync remain available, while vulnerability checks explicitly report its packages as unevaluated. The collector prints an end-of-life notice without mislabelling an otherwise complete inventory as partial. NVIDIA, Extras, third-party packages and runtime livepatch are outside this assessment.

Unresolved Ubuntu assessments remain review candidates. Unsupported releases, missing source metadata and packages absent from the advisory catalog are explicitly unevaluated. Stale or unavailable advisory data makes the check fail. Host checks cover available distribution advisories without a twelve-month publication cutoff. They assume official distribution packages; PPAs, third-party rebuilds, Debian backports repositories, specialized kernels/FIPS and runtime livepatch state need separate assessment.

## Check or synchronize through the API

In **Settings → Assets → Awarely Scan CLI**, create a token for the required application, source and environment. Prefer **check only** when inventory updates are unnecessary. Download its one-time credential file, move it to a private directory and restrict its permissions:

```sh
chmod 600 awarely-credentials.json

# Returns complete matching details in JSON; does not save inventory or email.
./dist/awarely-scan check --input my-app.cdx.json \
  --credentials awarely-credentials.json --output check-results.json

# Commits only the source bound to this credential; saves an exact receipt.
./dist/awarely-scan sync --input my-app.cdx.json \
  --credentials awarely-credentials.json --output sync-receipt.json
```

Use a new output path for each operation. Do not put tokens in command arguments, source control or build logs. `--credentials -` accepts credential JSON on standard input. No credential discovery, telemetry, redirects or insecure-TLS option is provided.

`sync` refuses partial inventories and requires `--allow-empty` to deliberately clear a source. The server preserves other sources and manual imports, merges shared components, and checks revisions to prevent lost updates. It does not send retrospective emails; new CVEs follow the organization's saved alert configuration. Read [API modes, limits and retry behavior](docs/api.md) before automation.

A successful `check` means the requested comparison finished, not that the application is secure. Inspect `matches`, component precision and `coverage.unevaluated`. An empty result does not cover unsupported inventories or vulnerabilities missing from the available advisory data. Application dependency checks retain their stated reporting window.

## Security and development

- [Security boundary and reporting](SECURITY.md)
- [Supported coverage and limits](docs/coverage.md)
- [Release verification](docs/releases.md)
- [Roadmap](docs/roadmap.md)
- [Contributing and tests](CONTRIBUTING.md)

Input parsing is bounded, duplicate JSON keys are rejected, file access is rooted, final symlinks/special files are rejected, and output is published atomically without replacement. CI includes race tests, parser fuzzing, runtime dependency checks and Linux syscall checks. These controls have defined limits; see the security document.

## License

Awarely Scan is licensed under [Apache-2.0](LICENSE). Go runtime notices are included in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The CLI license does not change the terms of the Awarely Monitor service.
