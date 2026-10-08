# Roadmap

## Current stable release

- Local CycloneDX 1.6 collection for documented npm/Python/DEB/RPM inputs.
- Explicit HTTPS checks with complete component-level JSON and coverage.
- Source-scoped, atomic inventory sync with revisions and idempotency.
- Scoped expiring credentials and MFA management.
- Synthetic end-to-end tests on Linux amd64 and arm64.

## Jenkins preview

The [Jenkins plugin](../jenkins-plugin/) uses the same CLI for Linux, npm, Python, Java, other managed-Syft inputs and existing SBOMs. It provides local, check and source-scoped sync actions, Jenkins Secret file credentials, bounded reports and configurable build policies. Preview releases remain separate from stable CLI releases. Untrusted pull-request jobs cannot use plugin API credentials or inventory the agent host.

## Future coverage

Additional distribution and ecosystem CVE coverage, package managers and container inventories require separate evidence and tests. They are not implied by this release's coverage.
