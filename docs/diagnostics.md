# Console diagnostics

Collection, check and sync emit progress on stderr; stdout, JSON files and exit codes retain their existing contracts. `--verbose` adds safe verification and operational details. Guided mode accepts `--verbose` too. Long managed collection and API operations emit a fixed heartbeat every 15 seconds without extra requests; prompts never produce heartbeats.

Automation can use `--log-format events`. After argument validation, stderr consists of payload-free lines `AWARELY_EVENT_V1 CODE` or `AWARELY_ERROR_V1 CODE`. Unknown codes must be ignored. Detailed events require `--verbose`. The allowed codes and fixed messages ship in `internal/diagnostics/catalog.json` inside each authenticated release archive. The Jenkins plugin authenticates that archive and bundles the same catalog when pinning a CLI release.

Events are informational, never proof of success. Consumers must check the process exit code and validate the resulting inventory/report. They must not interpret raw child output, error bodies, or arbitrary server messages as diagnostics. Missing/invalid arguments may still emit fixed usage text. Update and installation retain their dedicated progress output rather than this protocol.

No credential values, environment dumps, subprocess output or HTTP bodies are included. Human text may show quoted input/output paths and selected package findings in the guided summary. Unknown API errors use a generic fixed message. A failed or interrupted synchronization may have committed before its response was lost: inspect the configured source before retrying.
