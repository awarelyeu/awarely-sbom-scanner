Local-only preview: generate CycloneDX 1.6 inventories from npm lockfiles, declared package manifests and focused Debian/Ubuntu installed-package metadata.

Linux amd64 and arm64 archives include the binary, its component inventory, checksums and license notices. Verify GitHub build provenance before execution; see `docs/releases.md`.

There is no CVE scanning, remote inventory synchronization or Jenkins plugin in this release. These are subsequent stages. Known coverage gaps are explicit in the report and exit code. Host SBOMs preserve distro metadata; do not use generic Monitor OS matching until the server inventory model supports those fields.
