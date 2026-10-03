# Contributing

Use Go 1.27.1. Run:

```sh
go test -race -cover ./...
go vet ./...
python3 scripts/check_runtime.py
go test ./internal/inventory -run '^$' -fuzz '^FuzzJSON$' -fuzztime 10s -parallel 2
```

Run the other fuzz targets (`FuzzLock`, `FuzzRequirements`, `FuzzDPKG`) individually. Linux integration checks use `strace` and synthetic fixture files:

```sh
go build -trimpath -o dist/awarely-scan ./cmd/awarely-scan
python3 scripts/integration.py dist/awarely-scan
```

New collectors require a documented scope, bounded parsing, privacy fixtures and negative tests before being advertised. Never add project execution, arbitrary URL fetching, credentials, automatic uploads or package-manager invocations to the local collection path.

Keep generated inventories in `scan-output/`; outputs and build artifacts are ignored by Git. Do not commit customer data, tokens, local configuration or sibling repositories. Test fixtures must be synthetic. Awarely Monitor is a separate project and deploy process.

Changes to the API contract, dependency scope, collector authority or release workflow require security review. Release jobs run only from protected maintainer tags; untrusted pull requests must never receive signing credentials or production access.

Public documentation and commit messages should explain the CLI and its user-facing contract concisely. Keep service infrastructure, cloud account/resource identifiers, internal endpoints, access policies, deployment procedures and operational test evidence in the separate private project. Never copy internal runbooks or real account data into this repository, issues or releases.
# Documentation

The bilingual walkthrough source is `docs/guide.en.json` and `docs/guide.ro.json`. Render its Markdown with `python3 scripts/render_guides.py`; use `--check` to detect stale output. Public examples must use fictional names and reserved example API addresses, never service infrastructure identifiers or real credentials. Keep coverage claims aligned with the executable and API contract.
