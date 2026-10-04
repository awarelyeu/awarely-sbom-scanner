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

CI must pass for the exact commit before a maintainer creates a `v*` release tag. The release workflow re-runs tests and security checks, builds with the pinned Go version, packages license notices and publishes signed build provenance beside the archives. The initial release is marked prerelease. For an existing release, a maintainer may publish its original, verified attestation bundle as an additional asset without replacing its archive, checksum or tag.

Workflow permissions are read-only except the release job's explicit artifact/attestation permissions. The scanner repository has no production AWS credentials or Monitor deploy hooks. If a release is compromised, withdraw its download, publish an advisory and ship a new verified version; never silently replace an existing release archive.

## Simplified installation

The public `install.sh` asset automates the same archive provenance and checksum checks, without GitHub authentication. Review the script before running it. It checks prerequisites, stops on missing tools and publishes to `~/.local/bin/awarely-scan` without replacing an existing binary. It does not install system packages or run as root. See [guided installation](how-to.md#quick-install).
