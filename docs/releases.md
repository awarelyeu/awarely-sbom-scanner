# Verify a release

Release archives contain `awarely-scan`, `SHA256SUMS`, `binary-sbom.cdx.json`, license notices and documentation. Each GitHub release also includes a checksum list for the archives and GitHub build-provenance attestations. Starting with `v0.6.0-alpha.1`, each archive has a public `.sigstore.jsonl` verification bundle alongside it. No GitHub account or token is needed to download and verify these files.

Download the archive appropriate for Linux `amd64` (x86-64) or `arm64` (AArch64), its matching `.sigstore.jsonl` file and `SHA256SUMS` from this repository's Releases page. With a current GitHub CLI, verify the local bundle **before extracting/executing**. `--bundle` avoids the authenticated GitHub attestation API; trust-root updates still use the internet. Replace `VERSION` with the exact release tag:

```sh
gh attestation verify awarely-scan_VERSION_linux_amd64.tar.gz \
  --bundle awarely-scan_VERSION_linux_amd64.tar.gz.sigstore.jsonl \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml \
  --source-ref refs/tags/VERSION
```

Also compare the archive's SHA-256 against the release checksum file:

```sh
awk -v file=awarely-scan_VERSION_linux_amd64.tar.gz '$2 == file { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum --check selected-SHA256SUMS
```

Use the exact filenames on the release. Verification must succeed for the expected repository/workflow. A checksum from an unrelated location, or an attestation from another repository, is insufficient. The attestation records the source revision; it does not guarantee the code has no vulnerabilities.

Stop on any verification error. Extract into a directory you own and run the binary as your regular user. Local collection never needs an Awarely API token or an installer running as root. See the [complete walkthrough](how-to.md#install) for prerequisites, copyable commands, success checks and recovery steps.

## Maintainer process

CI must pass for the exact commit before a maintainer creates a `v*` release tag. The release workflow re-runs tests and security checks, builds with the pinned Go version, packages license notices and publishes signed build provenance beside the archives. The workflow initially marks releases as prerelease. After verifying the published archives and an installation/update smoke test, a maintainer promotes a stable tag such as v0.9.0 to a full release and marks it Latest. Tags containing a prerelease suffix remain prereleases; published tags and archives are never replaced. For an existing release, a maintainer may publish its original, verified attestation bundle as an additional asset without replacing its archive, checksum or tag.

Workflow permissions are read-only except the release job's explicit artifact/attestation permissions. The scanner repository has no production AWS credentials or Monitor deploy hooks. If a release is compromised, withdraw its download, publish an advisory and ship a new verified version; never silently replace an existing release archive.

## Simplified installation

The public `install.sh` asset automates the same archive provenance and checksum checks, without GitHub authentication. Review the script before running it. It checks prerequisites, stops on missing tools and publishes to `~/.local/bin/awarely-scan`. For an older installation, the authenticated candidate asks before performing an atomic upgrade with a private rollback backup. It does not install system packages or run as root. See [guided installation](how-to.md#quick-install).

## Explicit updates and rollback

From v0.9.0-alpha.1, `awarely-scan update --check` discovers eligible releases without changing files. `update` requires confirmation, verifies the archive against its public provenance bundle (repository, workflow, tag and GitHub-hosted runner), validates the binary checksum and startup, and replaces only the installed executable. It downloads a pinned temporary GitHub CLI verifier; no account or installed gh is needed. Stable installations stay stable unless `--prerelease` is explicitly requested; existing previews include newer previews. `--version TAG` selects an exact newer release and `--yes` enables approved automation.

`update --rollback` restores one previous local binary after confirmation. Backups are private and tied to the replacement digest. No remote inventory or credentials are changed. See the [user walkthrough](how-to.md#scanner-updates), including how to upgrade older CLIs with the installer.

Managed Syft versions and architecture digests are changed only in an Awarely release. Maintainers verify upstream signed checksum metadata and both archives, then run native/import/guided and offline interoperability checks on both architectures before publishing. The guided scanner has no arbitrary Syft version or latest-download setting. Previous tool cache entries remain available for rollback.
