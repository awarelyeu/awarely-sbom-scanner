# Awarely Scan v0.10.1 — updated Go runtime

This patch rebuilds the Linux amd64 and arm64 scanner with Go 1.27.2, which includes security fixes to the Go runtime and standard library. The vulnerability check runs against the new toolchain before release. See the [official Go release notes](https://go.dev/doc/devel/release#go1.27.2).

Collection, API operations, update verification and managed Syft 1.54.1 retain their behavior. There are no additional Go module dependencies. Existing installations can run `awarely-scan update --check`, then `awarely-scan update` to install the verified release.

The English and Romanian guides also describe configuration-only validation, configurable policy outcomes and build comparison in the separately versioned [Jenkins plugin](https://github.com/awarelyeu/awarely-scan-plugin). These plugin features are delivered in its own release.

[English guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md) · [Ghid în română](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.ro.md)
