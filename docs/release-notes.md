# Guided Linux and application scans

Start `awarely-scan` in a terminal, or run `awarely-scan guided`. Choose Linux, npm, Python, Java or other application ecosystems. The scanner checks inputs, explains missing prerequisites, creates a private SBOM and offers local export, API check or scoped API sync.

Optional Syft preparation uses a fixed, digest-verified archive and requires confirmation. It needs no separately installed Cosign, gh, Java or Python runtime to inspect existing artifacts. The initial Awarely installer verifies release provenance using public bundles without GitHub login. Project builds and dependency installation remain under your control.

API transmission requires a separate confirmation showing its destination and source. Partial inventories cannot sync. Native host/app/import commands retain their offline behavior; existing automation commands remain supported.

See the [English guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.7.0-alpha.1/docs/how-to.md) and [Romanian guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.7.0-alpha.1/docs/how-to.ro.md). This remains a prerelease pending the user walkthrough. Jenkins is a later stage. Ecosystem CVE coverage is unchanged; inventory support is not a vulnerability verdict.
