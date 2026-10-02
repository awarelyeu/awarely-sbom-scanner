# API modes

Local `app` and `host` collection need no account and never contact the API. Awarely Monitor Pro enables separately scoped machine credentials in Settings → Assets. Organization managers must satisfy the sensitive-action MFA gate to create, view or revoke them. Save the generated configuration once; the secret cannot be retrieved later. Rotation can reuse an existing source. A new source is a new independently maintained inventory snapshot, not merely a new token.

## Check

`awarely-scan check --input app.cdx.json --credentials credentials.json --output check.json`

Posts a normalized, minimized snapshot. The service checks the preceding 12 months by advisory publication date, across its available CVE feeds, and returns full matching component details and descriptions. It never saves submitted inventory or sends email. Multiple feed records for one identifier are merged before evaluating version ranges. Distinct CVE/GHSA identifiers are not guaranteed to be alias-deduplicated.

The JSON contains `components`, `matches`, `summary` and `coverage`. Each match refers to submitted components by `componentIndex`, and includes precision and advisory products/ranges. `version` means the declared exact version falls inside a comparable advisory range, not proof of exploitation or deployment. `product` requires review. Missing versions and unassessed distribution packages appear in `coverage.unevaluated`. Distribution checks also return `coverage.distributionEvaluated`, `coverage.distributionCatalogs` and per-match `distributionEvidence`, including the source-package version and fixed distribution version. Ubuntu entries without a published fix can include untriaged cases and remain `product` matches requiring review. No saved inventory or email is changed by `check`. Unsupported ecosystems must not be interpreted as unaffected. Partial inputs can be checked but remain partial in coverage.

## Sync

`awarely-scan sync --input app.cdx.json --credentials credentials.json --output receipt.json`

The credential fixes application/source/tenant on the server. Sync replaces only that source. Common package identities and versions count once across applications; replacing a source does not remove another source's or a manual import's membership. The saved source is used by Monitor reports and configured alerts. To see it in an already-open browser, reload the inventory. No additional Save click is needed for an API commit.

The CLI reads the current source revision and commits with `If-Match`. Another writer wins safely: a stale revision returns HTTP 409 and the CLI exits 6. Inspect/recollect before retrying. For explicit automation, use `--expected-revision REV --idempotency-key KEY` (16–80 letters/digits/underscore/hyphen). Transport/503 retries reuse the same request/revision/key, with bounded backoff. Replay records are retained for at least 24 hours while present; reuse with a different payload fails. A new CLI invocation creates a new key unless one is provided.

An uncertain transport failure may occur after a commit. If exact retry reconciliation is needed, retain an explicit revision/key outside the CLI. The next ordinary sync reads the latest revision and replaces the same source; it does not append duplicates. If saving the local receipt fails after the API committed, exit 4 does not roll back the server. Fix the output location and inspect the inventory.

Partial snapshots cannot sync, including package.json fallbacks, requirements files or unresolved workspace entries. Use local upload/check to review these inputs. Empty source replacement requires `--allow-empty`; otherwise deletion is refused. Revoking a token does not delete its inventory. Clearing a source requires a new complete empty snapshot and explicit confirmation. Organization deletion disables machine access and deletes its managed inventory.

## Limits and errors

| Boundary | Limit |
| --- | --- |
| Normalized request | 2 MiB; 5,000 components |
| Inventory per organization | 5,000 unique identities; 50 applications; 2 MiB combined normalized data |
| Scanner sources | 50 per organization; 2 MiB source snapshot storage |
| Credentials | 100 active; 200 directory entries until expiry cleanup; 1–90 days |
| Check response | 5 MiB; 2,000 advisory identifiers; 10,000 component matches |
| Check budget | 6 per minute per organization and credential |
| Sync API budget | 30 requests per minute per organization and credential (GET counts) |
| In-flight requests | 2 per organization per operation |
| Catalog freshness | At most 48 hours |

Global gateway/concurrency limits may also return 429 during load. Respect `Retry-After`; the CLI does not automatically retry a 429 or 409. Size/resource limits return an error instead of a truncated success. A stale, corrupt or unavailable catalog returns failure, not an all-clear. 401 indicates invalid/expired/revoked credentials; 403 indicates insufficient scope or changed access; 422 rejects incomplete or unconfirmed empty snapshots.

There is no `--insecure`, redirect following, automatic credential discovery, project execution or background upload. Credentials and outputs must be protected as sensitive files. The default origin is supplied in your downloaded configuration, not discovered from repository contents.
