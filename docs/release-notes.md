# Awarely Scan v0.10.0 — managed collection for automation

Automated builds can now collect npm, installed Python, Java and other supported application ecosystems through `awarely-scan syft`. It uses the same verified, release-pinned Syft 1.54.1 as guided mode, without interactive prompts. `--allow-download` explicitly permits downloading a missing pinned tool; otherwise collection requires its existing verified cache.

The collector reads an existing application directory, writes a new private CycloneDX inventory and preserves partial-coverage warnings. It does not build the project, install dependencies or contact Monitor. Checks and synchronization remain separate explicit commands. Native `app --ecosystem npm|python` can limit a mixed directory to one ecosystem. Omitting the selector preserves combined-manifest behavior. Existing guided, update and API workflows retain their behavior.

The [Jenkins integration](https://github.com/awarelyeu/awarely-scan-plugin) is versioned separately and uses this CLI. See the [English guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md#syft-automation) or [Romanian guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.ro.md#syft-automation).

Coverage is unchanged. Unsupported ecosystems remain explicitly unevaluated; no matches is not an assurance of security.
