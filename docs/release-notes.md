# Distribution advisory checks

Host inventories now preserve source-package names and versions, including binary-only rebuilds. API checks evaluate supported Debian/Ubuntu packages against official distribution advisories and report fixed versions, advisory links and per-component evidence. Backported fixes use Debian version ordering. Unknown assessments and unsupported inputs remain explicit; unavailable or stale data cannot produce a clean result.

Local collection remains offline and rootless. Recollect host inventories created with earlier releases to include source-package metadata. Read the [coverage](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.3.0-alpha.1/docs/coverage.md) and [API](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.3.0-alpha.1/docs/api.md) documentation for supported releases and report semantics.
