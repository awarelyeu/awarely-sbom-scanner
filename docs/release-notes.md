# Verified updates and rollback

Check for a newer release with `awarely-scan update --check`, then run `awarely-scan update` and confirm. The updater verifies signed release provenance, the binary digest and startup before atomic replacement, and keeps one private rollback backup. `awarely-scan update --rollback` restores the previous binary without network access. Scans never trigger updates.

Older installations can upgrade through this release's installer after verification and confirmation, without manually moving the old binary. Stable installations stay on stable releases; prerelease installations also see newer previews. No GitHub login, system gh or root access is needed.

Managed Syft is now **1.54.1**, with verified architecture-specific digests. It changes only through a tested Awarely release. `awarely-scan version --tools` shows both versions; the next Syft scan requests consent if the new tool is not cached.

The English and Romanian walkthroughs include initial upgrade, subsequent updates, troubleshooting and rollback. This remains a prerelease; ecosystem CVE coverage is unchanged.
