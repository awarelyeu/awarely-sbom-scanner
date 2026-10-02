# Awarely Scan — Linux SBOM Generator & Software Inventory

[![CI](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Generate a local **CycloneDX SBOM** from application manifests or a focused selection of installed Debian/Ubuntu/Rocky Linux/AlmaLinux packages. Local collection runs without root, package installation, project scripts, telemetry or network access. Explicit `check` and `sync` commands communicate with Awarely Monitor over HTTPS.

Built for [Awarely Monitor](https://monitor.awarely.ro/en), with a standalone local workflow you can inspect and use independently.

**Status: API preview for Linux amd64 and arm64.** Local collection is independent of an account. Remote operations require Awarely Monitor Pro and a scoped machine credential created by an organization manager with MFA. Jenkins integration is the next stage.

| Workflow | Available |
| --- | --- |
| Local SBOM file | Yes |
| CVE check through the Awarely API | Yes, without changing saved inventory |
| Inventory synchronization through the Awarely API | Yes, replaces one configured source |
| Jenkins plugin using the same CLI | Planned |

## Quick start

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
| Rocky Linux/AlmaLinux RPM database | Installed EVR versions | Selected packages plus installed capability providers; SQLite/WAL and Berkeley DB hash |

Application collection reads only supported manifests in the directory you choose. It does not recursively discover repositories, inspect `node_modules`, read `.env`, execute scripts or fetch registries. npm shrinkwrap takes precedence over package-lock; package.json is a fallback. Workspace links are not followed and are reported as partial coverage.

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
