# Awarely Scan v0.9.0 — first stable release

Generate a local CycloneDX SBOM, check supported package versions through Awarely Monitor, or synchronize one configured inventory source. Guided setup includes input recovery, readable check summaries and reuse of existing SBOMs. Local collection is available without an account; API operations require Monitor Pro and a scoped credential.

This release retains the collector and API behavior of v0.9.0-alpha.1. Managed Syft remains pinned to **1.54.1**. It is downloaded only with consent and verified against release-specific digests. Syft collects package identities; Awarely performs vulnerability assessment for the documented supported ecosystems and distributions. Unsupported or incomplete assessments remain explicit, including Go, NuGet, Composer, RubyGems, Cargo and Amazon Linux 2.

Upgrade an existing v0.9.0-alpha.1 installation with:

```sh
awarely-scan update --check
awarely-scan update
awarely-scan version --tools
```

The update asks for confirmation and verifies repository, workflow, tag, build provenance and checksums before atomic replacement. One private backup supports rollback. Older versions without the update command can use this release's installer. No root or GitHub login is required. After upgrading, stable installations receive stable releases by default.

See the [English walkthrough](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md) or [Romanian walkthrough](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.ro.md) for installation, scanning, API credentials and interpretation of results. Coverage limits still apply; zero matches is not a security guarantee. Jenkins integration is the next planned stage.
