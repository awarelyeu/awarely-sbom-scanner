# Roadmap

## Current stable release

- Local CycloneDX 1.6 collection for documented npm/Python/DEB/RPM inputs.
- Explicit HTTPS checks with complete component-level JSON and coverage.
- Source-scoped, atomic inventory sync with revisions and idempotency.
- Scoped expiring credentials and MFA management.
- Synthetic end-to-end tests on Linux amd64 and arm64.

## Next: Jenkins plugin

Build a dedicated plugin using this same CLI after the CLI/API test gates pass. Offer local, check and sync modes, use Jenkins Credentials and publish results. Untrusted pull-request jobs must not receive inventory-write credentials.

## Future coverage

Additional distribution and ecosystem CVE coverage, package managers and container inventories require separate evidence and tests. They are not implied by this release's coverage.
