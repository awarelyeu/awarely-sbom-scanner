# Security

## Scope of this preview

The executable has no network client, credential discovery, remote configuration, auto-update, plugin loading or subprocess execution. No API endpoint is introduced by this repository. The `check` and `sync` commands return an unavailable error.

Use a non-privileged account and select a directory or root filesystem you are authorized to inspect. Only Linux amd64/arm64 release binaries are supported. macOS is used for development tests.

## Trust boundaries

Package files and package database contents are untrusted data. We read regular files through Go's `os.Root`, which confines path resolution against parent-directory and symlink traversal. The final input file must not be a symlink, multiply hard-linked file, FIFO, socket or device. Size, JSON depth, string lengths, component count and processing deadlines are bounded. Output publication uses a fully written private temporary file and an atomic hard link that refuses an existing destination.

The user-selected root and output directory are authority granted by the caller. A hostile process running as the same OS user, a compromised kernel/filesystem, or a hostile mount can defeat normal filesystem assumptions. This utility is not an OS sandbox. It does not prove the completeness or truthfulness of client-supplied inventory. Do not run it with production credentials in its environment or as root when a normal account suffices.

The deadline is checked during normal reads and parser loops; a kernel-blocked filesystem operation may not return promptly. Choose local filesystems. For automation, enforce an external process deadline and memory budget as well.

## Data minimization

Exports contain package identities/versions, package evidence, an explicit application label, distro metadata where applicable, input basenames and fixed warning codes. URLs, dependency installation specs, project scripts, file contents, hostnames and absolute source paths are not copied into the SBOM. Application labels are supplied by the operator. Software names can themselves be sensitive; protect the resulting inventory.

Names are validated and JSON is encoded structurally. No raw project error line, install spec or credential-bearing URL is written into a diagnostic. New outputs use mode 0600; existing files are never replaced.

## Testing and release policy

Unit and race tests exercise traversal, special files, malformed/duplicate JSON, package identity, partial coverage, version precision and no-overwrite output. Fuzz targets cover JSON, npm locks, requirements and dpkg. CI checks the executable dependency graph for networking/subprocess packages and traces Linux system calls on synthetic fixtures.

Only test data is used in tests. Never scan a live service or upload an inventory to production as part of this preview's CI. Runtime dependency checks and tests are evidence for the exercised paths, not a guarantee that no vulnerability exists.

Release archives have checksums, GitHub build provenance and a component inventory for the binary. Verify both the digest and the expected signing repository/workflow. A digest alone does not establish who produced a file.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/awarelyeu/awarely-sbom-scanner/security/advisories/new) when enabled. Do not put real tokens, private inventory or exploit details in a public issue. Provide the version, platform, smallest synthetic reproduction and observed impact. We triage confirmed issues and document affected versions and fixes in release notes.

Before API functionality is released, additional server-side tenant authorization, scoped/revocable credentials, quotas, independent check/write permissions and integration tests are required. A signed CLI must never be treated as a trusted API client.
