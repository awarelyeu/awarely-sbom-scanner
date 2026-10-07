# Security

## Scope of this preview

Local collection never uses the network. Explicit `check` and `sync` commands use an HTTPS client. Guided mode adds consented tool preparation and optional API actions. There is no credential discovery, background auto-update or plugin loading. Subprocess execution is isolated to the optional Syft runner and explicit verified-update boundary (temporary pinned verifier and authenticated candidate startup check). The server treats every client and inventory as untrusted; owning a signed binary grants no API authority.

Use a non-privileged account and select a directory or root filesystem you are authorized to inspect. Only Linux amd64/arm64 release binaries are supported. macOS is used for development tests.

## Trust boundaries

Package files and package database contents are untrusted data. We read regular files through Go's `os.Root`, which confines path resolution against parent-directory and symlink traversal. The final input file must not be a symlink, multiply hard-linked file, FIFO, socket or device. Size, JSON depth, string lengths, component count and processing deadlines are bounded. Output publication uses a fully written private temporary file and an atomic hard link that refuses an existing destination.

The user-selected root and output directory are authority granted by the caller. A hostile process running as the same OS user, a compromised kernel/filesystem, or a hostile mount can defeat normal filesystem assumptions. This utility is not an OS sandbox. It does not prove the completeness or truthfulness of client-supplied inventory. Do not expose unrelated production credentials in its environment or run it as root when a normal account suffices. API credentials belong in an explicit owner-only file or standard input.

The deadline is checked during normal reads and parser loops; a kernel-blocked filesystem operation may not return promptly. Choose local filesystems. For automation, enforce an external process deadline and memory budget as well.

## Data minimization

Exports contain package identities/versions, package evidence, an explicit application label, distro metadata where applicable, input basenames and fixed warning codes. URLs, dependency installation specs, project scripts, file contents, hostnames and absolute source paths are not copied into the SBOM. Application labels are supplied by the operator. Software names can themselves be sensitive; protect the resulting inventory.

Names are validated and JSON is encoded structurally. No raw project error line, install spec or credential-bearing URL is written into a diagnostic. New outputs use mode 0600; existing files are never replaced.

## Testing and release policy

Unit and race tests exercise traversal, special files, malformed/duplicate JSON, package identity, partial coverage, version precision and no-overwrite output. Fuzz targets cover JSON, npm locks, requirements, dpkg, RPM databases, headers, WAL and dependency expressions. CI rejects external runtime modules, plugin/cgo dependencies, and networking/subprocess dependencies in the native collector. Only the producer package may import os/exec. It traces Linux local-mode system calls on synthetic fixtures. Remote client tests cover certificate verification, redirect rejection, response bounds, consistency and retry identity.

Automated tests use synthetic data and isolated environments. CI must not upload inventory to production. Linux amd64 and arm64 are tested. Test results cover the exercised paths and do not guarantee that no vulnerability exists.

Release archives have checksums, GitHub build provenance and a component inventory for the binary. Verify both the digest and the expected signing repository/workflow. A digest alone does not establish who produced a file.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/awarelyeu/awarely-sbom-scanner/security/advisories/new) when enabled. Do not put real tokens, private inventory or exploit details in a public issue. Provide the version, platform, smallest synthetic reproduction and observed impact. We triage confirmed issues and document affected versions and fixes in release notes.

## Remote operations

The credential file must be owned by the current user with no group/other permission bits, and pass the same regular-file/no-symlink/no-hardlink checks as other input. API origins require HTTPS, without URL credentials, paths, queries or fragments. TLS certificate validation is mandatory; redirects and environment proxy discovery are disabled. The credential grants authority to the configured origin: obtain this file only from your trusted Awarely account.

Requests project only supported package identities, versions and evidence from a CycloneDX file. Raw SBOM metadata, URLs, filenames and project contents are not uploaded. Requests, responses, deadlines and JSON complexity are bounded. Credentials and remote response bodies are not printed in errors. Reports and receipts use the same private no-overwrite publication as local outputs.

Create scoped, expiring credentials in your Awarely account with MFA enabled. Prefer check-only access when updates are unnecessary, and revoke credentials when their work is finished. Check does not save inventory or send alerts. Sync updates only its assigned inventory source.

Sync requires a complete selected-input snapshot, revision and idempotency key. Server quotas and size limits fail closed rather than truncate. The signature, evidence labels and completeness claim are not proof of a client's honesty: a principal with inventory-write permission can intentionally replace its own source. Do not grant that credential to untrusted jobs or pull requests.

No distribution-advisory solver is included. Distro packages cannot receive a confirmed upstream-semver match. A successful response is not a security certification.

RPM collection reads bounded regular-file snapshots directly, without SQL execution, native database libraries, recovery writes or package-manager execution. SQLite WAL checksums and commit boundaries are validated in memory. Database changes or malformed page/overflow references fail without publishing an inventory. Installed vendor/module fields are untrusted inventory evidence, not a package-signature attestation.

## Optional SBOM producers

Syft is optional. It may be installed/run separately, or prepared by the guided scanner after an explicit confirmation. The managed runner accepts only a fixed Linux amd64/arm64 archive whose SHA-256 was verified by maintainers against the upstream signed release. The digest pins are part of the signed Awarely release; archive verification is repeated on every use. No PATH executable or user Syft configuration is trusted. The runner never uses sudo or installs project dependencies. Import accepts bounded CycloneDX JSON, retains allowlisted package identities and labels them imported-sbom. Coverage describes the selected file, not producer authenticity or completeness of the deployment. Unsupported identities/variants or missing versions produce partial input; sync refuses partial replacement. Source URLs and file paths are never followed. Protect intermediate Syft output too, because it can contain local paths or metadata before normalization. Run third-party collectors against explicitly selected inputs without root, using resource/network isolation for untrusted material.

## Guided tool boundary

An approved download uses HTTPS with certificate verification, fixed release URLs, an explicit GitHub redirect allowlist, bounded response sizes/deadlines, and no environment proxies or credentials. The owner-only cache stores the original archive; only its regular syft executable is extracted to a fresh private workspace. Extracted executables and raw producer output are removed after the run.

Syft receives a fixed offline configuration, selected catalogers, an isolated working directory and a minimal environment without cloud/API credentials, user configuration or executable search paths. Output and execution time are bounded; cancellation kills the process group. These controls are **not an OS sandbox or a memory limit**. Do not scan hostile projects outside a separate sandbox with memory/filesystem/network restrictions. CI additionally verifies offline behavior under a network namespace and syscall tracing.

The wizard defaults to a local export. Download/execution and API transmission require separate explicit choices. It displays the credential's destination/application/source before confirmation; partial snapshots cannot sync. An empty inventory cannot clear a source in guided mode. Existing noninteractive commands retain their contracts. API credential acquisition, package-manager changes and project builds remain operator-controlled.

## Explicit release updates

Update discovery is a hint, not authentication. An update must verify the release archive's public provenance against the expected repository, workflow and exact tag before extracting or executing the candidate. The temporary verifier has an embedded upstream SHA-256 pin and receives no user credentials or configuration. Downloads, expanded archives and subprocess output are bounded. A failed trust check cannot replace the installed binary.

Updates require a regular non-root user, a trusted owned installation path and an exclusive lock. Staging and backup writes are flushed before atomic replacement. Rollback restores the matching private local backup; it is not an arbitrary remote downgrade. Same-user modification of the installed binary or backup is outside the local trust boundary. Managed Syft remains pinned per Awarely release; update checks never run during ordinary scans.
