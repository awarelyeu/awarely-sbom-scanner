# Rocky Linux and AlmaLinux support

The existing Linux amd64/arm64 binaries now detect Rocky Linux and AlmaLinux automatically. Local inventory, explicit API checks and source-scoped inventory sync support RPM packages on releases 8/9/10.

Local collection reads bounded SQLite/WAL and Berkeley DB snapshots without root, network access, subprocesses or package installation. API checks use official distribution advisories and RPM EVR ordering, preserving architecture, vendor, module stream and backported revisions. Unsupported or unassessed packages remain explicit in coverage.

See [coverage](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.4.0-alpha.1/docs/coverage.md) and [API semantics](https://github.com/awarelyeu/awarely-sbom-scanner/blob/v0.4.0-alpha.1/docs/api.md). Jenkins integration remains a later phase.
