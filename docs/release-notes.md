API preview: local CycloneDX inventory, explicit HTTPS checks and source-scoped inventory sync on Linux amd64 and arm64.

Machine credentials are scoped, expiring and revocable; manage them with MFA in Monitor Settings → Assets. Check returns complete component evidence without saving or emailing. Sync uses optimistic concurrency and idempotency, preserves other sources and manual inventories, and refuses partial or unconfirmed empty snapshots.

Local commands still use no network, subprocesses or telemetry. There are no third-party Go runtime modules. Read `docs/api.md` and `SECURITY.md` before using remote operations. Distribution-specific CVE evaluation is not implemented: Debian/Ubuntu identities are retained, and unevaluated host components are explicit in check reports.

Archives include SHA-256 checksums, binary component inventories and GitHub build provenance. Verify the expected repository/workflow before execution. Jenkins is not included.
