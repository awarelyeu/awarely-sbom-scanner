# Roadmap

## Current: local collection preview

- Local CycloneDX 1.6 export for documented application and DEB inputs.
- Explicit evidence, coverage warnings and bounded filesystem/parser behavior.
- Independent public source, tests and release provenance.

## Next: API check

Versioned normalized payload and complete results, scoped/revocable machine credentials, per-tenant authorization, resource quotas and a worker without inventory/alert permissions. Check must leave saved inventory unchanged. Require a separate staging environment and tenant-isolation tests before production activation.

## Then: inventory sync

Source-scoped atomic snapshots, idempotency, optimistic concurrency and shared-component memberships. Incomplete snapshots must not delete existing data. Preserve OS distro/package identity in the Monitor model before supporting OS matching. Existing browser MFA requirements and API read keys must not be weakened or silently expanded.

## Jenkins

A dedicated plugin will invoke the same CLI on a supported build agent, offer local/check/sync modes, use Jenkins Credentials and publish results. Untrusted pull-request jobs must not receive inventory-write credentials.

These are planned capabilities, not current features or delivery-date promises.
