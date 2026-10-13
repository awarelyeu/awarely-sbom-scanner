# v0.12.0 — NuGet and Go CVE checks

NuGet/.NET package libraries and Go modules can now be assessed through the Monitor API and the Jenkins integration. The service uses typed package advisories, exact ecosystem identities, NuGet version ordering and Go SemVer/pseudo-version ordering. Unknown versions or advisory syntax remain explicit coverage gaps; product-level findings never become version-confirmed policy failures. Go toolchain/stdlib assessment remains outside the module check.

Guided option 5 and the English/Romanian guides explain how to prepare dependency files, check an inventory and rescan after remediation. The managed Syft version remains 1.54.1. No new credentials, build execution or installation permissions are introduced.

# v0.11.0 — Clear progress and safe diagnostics

Collection and API commands show progress, waiting messages, timings and bounded check summaries. Optional `--verbose` explains cache verification and tool isolation. A payload-free v1 diagnostic-code interface lets Jenkins show specific recovery guidance without forwarding raw output. Existing exit codes, JSON artifacts, consent, pin verification and API behavior are preserved. Syft remains 1.54.1.

# Awarely Scan v0.10.1 — updated Go runtime

This patch rebuilds the Linux amd64 and arm64 scanner with Go 1.27.2, which includes security fixes to the Go runtime and standard library. The vulnerability check runs against the new toolchain before release. See the [official Go release notes](https://go.dev/doc/devel/release#go1.27.2).

Collection, API operations, update verification and managed Syft 1.54.1 retain their behavior. There are no additional Go module dependencies. Existing installations can run `awarely-scan update --check`, then `awarely-scan update` to install the verified release.

The English and Romanian guides also describe configuration-only validation, configurable policy outcomes and build comparison in the separately versioned [Jenkins plugin](https://github.com/awarelyeu/awarely-scan-plugin). These plugin features are delivered in its own release.

[English guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md) · [Ghid în română](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.ro.md)
