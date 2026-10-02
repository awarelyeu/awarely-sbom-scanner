# Awarely Scan — Linux SBOM Generator & Software Inventory

[![CI](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/awarelyeu/awarely-sbom-scanner/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Generate a local **CycloneDX SBOM** from application manifests or a focused selection of installed Debian/Ubuntu packages. Awarely Scan runs without root, package installation, project scripts, telemetry or network access.

Built for [Awarely Monitor](https://monitor.awarely.ro/en), with a standalone local workflow you can inspect and use independently.

**Status: early local-only preview.** This version collects inventory. It does not check CVEs, update a remote inventory or provide a Jenkins plugin yet.

| Workflow | Available |
| --- | --- |
| Local SBOM file | Yes |
| CVE check through the Awarely API | Planned |
| Inventory synchronization through the Awarely API | Planned |
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

Omit `--select` to use the documented [focused server profile](docs/coverage.md). Use `--all-packages` to explicitly include every installed DEB package instead. `--root` accepts a selected offline Debian/Ubuntu root filesystem.

The output file is created with owner-only permissions and is never overwritten. Choose a new filename for each snapshot. SBOMs can disclose your software stack; keep them private unless you intend to share them.

## What is collected?

| Input | Meaning of the versions | Coverage |
| --- | --- | --- |
| npm `package-lock.json` / `npm-shrinkwrap.json` v2/v3 | Resolved versions | Includes entries for direct, transitive, development and optional dependencies; does not claim they are installed |
| `package.json` fallback | Declared versions | Partial; ranges remain unknown versions, transitive dependencies unresolved |
| `requirements.txt` | Declared requirements | Partial; does not install packages, resolve dependencies or follow includes/URLs |
| Debian/Ubuntu package database | Installed versions | Selected packages plus Depends/Pre-Depends closure; distro, architecture, epoch/revision preserved |

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
| 6 | API check/sync requested, but not implemented; nothing sent |

## Using the file with Awarely Monitor

Application SBOMs can be reviewed and uploaded in **Settings → Assets**. Saving an import changes the selected inventory and can affect its configured alerts. Collection itself has no interaction with your Awarely account.

**Linux package matching is not ready in the current Monitor inventory model.** This CLI preserves distro-qualified package identities, but the existing importer does not retain all of those fields. Keep host SBOMs locally for now. Do not treat generic version comparisons as confirmation for distro packages with backported fixes.

The CLI requires no account or API token for local collection. Future API operations will be explicit and authenticated separately.

## Security and development

- [Security boundary and reporting](SECURITY.md)
- [Supported coverage and limits](docs/coverage.md)
- [Release verification](docs/releases.md)
- [Roadmap](docs/roadmap.md)
- [Contributing and tests](CONTRIBUTING.md)

Input parsing is bounded, duplicate JSON keys are rejected, file access is rooted, final symlinks/special files are rejected, and output is published atomically without replacement. CI includes race tests, parser fuzzing, runtime dependency checks and Linux syscall checks. These controls have defined limits; see the security document.

## License

Awarely Scan is licensed under [Apache-2.0](LICENSE). Go runtime notices are included in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The CLI license does not change the terms of the Awarely Monitor service.
