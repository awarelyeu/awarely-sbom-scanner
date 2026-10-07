# A clearer guided scanning experience

The guided menu now lets you correct paths, labels, result directories and credential files without restarting. Use `b` to go back, `q` to quit, and option 6 to reopen a saved Awarely SBOM for check or sync. Relative paths, `~/` and quoted paths are supported without shell execution.

Terminal-only colors respect `NO_COLOR` and `TERM=dumb`. API checks include a readable `check-summary.txt` alongside the complete JSON evidence. Check retries need a new confirmation; uncertain syncs are never retried automatically. Report-saving recovery does not repeat an API request.

Local-first defaults, private files, verification of optional Syft, explicit transmission consent and partial-inventory sync restrictions remain in place. Noninteractive command contracts and ecosystem assessment coverage are unchanged.

See the [English guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.md) or [Romanian guide](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/how-to.ro.md). This is a prerelease.
