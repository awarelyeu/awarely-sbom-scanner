# Plugin releases and verification

Plugin tags use `jenkins-vVERSION`; CLI tags use `vVERSION`. The monorepo keeps the implementation and compatibility contract together, while allowing independent plugin releases. The HPI is not currently listed in the Jenkins Update Center.

Download the HPI, its matching `.sigstore.jsonl` file and `SHA256SUMS` from the exact plugin release. Before installing controller code, verify the public provenance bundle with an up-to-date GitHub CLI. Substitute the release's exact tag and filename:

```sh
gh attestation verify awarely-scan-jenkins-VERSION.hpi \
  --bundle awarely-scan-jenkins-VERSION.hpi.sigstore.jsonl \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/jenkins-release.yml \
  --source-ref refs/tags/jenkins-vVERSION \
  --deny-self-hosted-runners
sha256sum --check SHA256SUMS
```

Download the dependency inventory JSON too when checking the complete checksum list. On macOS, use `shasum -a 256 -c SHA256SUMS`. Public bundles do not require a GitHub account; trust-root updates still need internet access. Stop if provenance or digests fail. The attestation identifies the build source, not a guarantee that code has no vulnerabilities.

Each release contains the HPI, a CycloneDX dependency inventory, checksum list and public attestation bundles. The dependency inventory includes provided Jenkins/plugin dependencies, not only JARs embedded in the HPI. The HPI carries Maven license metadata; this plugin is Apache-2.0 and its Jenkins dependencies retain their own licenses.

## Maintainers

1. Authenticate a published CLI release with `python3 jenkins-plugin/scripts/pin-cli.py --version vVERSION`. This verifies both architectures against repository, workflow, tag and GitHub-hosted-runner provenance before deriving archive and executable pins. No CLI binary is executed during pin generation.
2. Review the pin changes, set the explicit plugin version in `pom.xml`, update both walkthroughs and release notes, and complete security review of changed authority/dependencies/release workflows.
3. Run `mvn -B -ntp -f jenkins-plugin/pom.xml verify` and real Pipeline/Freestyle acceptance tests on isolated Linux amd64 and arm64 agents. Test denied credentials, untrusted jobs, report permissions, interrupted processes, modified caches and incomplete coverage.
4. Merge only after CI passes for the reviewed commit. Create a new `jenkins-vVERSION` tag pointing to the verified merge commit, or a signed annotated tag. The release workflow repeats tests and authenticates the CLI pins, builds the HPI/SBOM and publishes provenance with an initial prerelease designation.
5. Verify the published artifacts and install them in staging before promotion. Keep alpha tags as prereleases; never rewrite a published tag or replace its assets.

Updating CLI pins is a plugin release decision. Build jobs cannot run arbitrary versions or automatic updates. A compromised release requires withdrawal/advisory and a new version, not silent replacement.
