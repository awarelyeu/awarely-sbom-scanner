# Verify a release

Release archives contain `awarely-scan`, `SHA256SUMS`, `binary-sbom.cdx.json`, license notices and documentation. Each GitHub release also includes a checksum list for the archives and GitHub build-provenance attestations.

Download the archive appropriate for Linux `amd64` (x86-64) or `arm64` (AArch64) from this repository's Releases page. With a current GitHub CLI, verify its attestation **before extracting/executing**:

```sh
gh attestation verify awarely-scan_VERSION_linux_amd64.tar.gz \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml
```

Also compare the archive's SHA-256 against the release checksum file:

```sh
sha256sum --check SHA256SUMS
```

Use the exact filenames on the release. Verification must succeed for the expected repository/workflow. A checksum from an unrelated location, or an attestation from another repository, is insufficient. The attestation records the source revision; it does not guarantee the code has no vulnerabilities.

Extract into a directory you own and run the binary as your regular user. Local collection never needs an Awarely API token or an installer running as root.

## Maintainer process

CI must pass for the exact commit before a maintainer creates a `v*` release tag. The release workflow re-runs tests and security checks, builds with the pinned Go version, packages license notices and emits signed build provenance. The initial release is marked prerelease.

Workflow permissions are read-only except the release job's explicit artifact/attestation permissions. The scanner repository has no production AWS credentials or Monitor deploy hooks. If a release is compromised, withdraw its download, publish an advisory and ship a new verified version; never silently replace an existing release archive.
