# Awarely Scan for Jenkins

**Preview: 0.1.0-alpha.1. Test on a staging controller before production use.**

[Download and verify the HPI](docs/releases.md). Pins: CLI v0.10.0 and managed Syft 1.54.1.

Generate an SBOM during a build, check it with Awarely Monitor, and explicitly synchronize one inventory source when appropriate. The plugin uses the same CLI and managed Syft as the terminal workflow. It does not build your application or install its dependencies.

[English walkthrough](docs/how-to.md) · [Ghid în română](docs/how-to.ro.md) · [Security boundaries](SECURITY.md)

The plugin lives in this repository under `jenkins-plugin/`. Plugin versions, CLI versions and release artifacts are separate. This repository's release download is not a claim of inclusion in the Jenkins Update Center.

## Supported workflows

| Collector | Input in the build workspace | Collection |
| --- | --- | --- |
| `npm` | Directory with an npm lockfile | Native manifest collection |
| `npm-syft` | Built/installed Node.js directory | Managed Syft |
| `python` | Directory with requirements.txt | Native, partial inventory |
| `python-syft` | Directory containing an installed virtual environment | Managed Syft |
| `java` | Built Java artifacts and their dependencies | Managed Syft |
| `other` | NuGet, Go, Composer, RubyGems or Cargo application files | Managed Syft; CVE assessment currently unevaluated |
| `linux` | The Linux Jenkins agent | Focused packages, or all installed packages |
| `import` | An external CycloneDX application SBOM | Validated application-package import |
| `existing` | A previously generated Awarely inventory | Reuse without rescanning |

Actions are `local` (default), `check` and `sync`. Linux collection inventories the **agent**, not a container image or production server. See the CLI [coverage contract](../docs/coverage.md).

## Build from source

Use JDK 21 and Maven with the Jenkins baseline declared in `pom.xml`:

```sh
mvn -B -ntp -f jenkins-plugin/pom.xml verify
```

The output is `jenkins-plugin/target/awarely-scan.hpi`. Development tool manifests deliberately fail closed until release archive and executable digests have been authenticated. Do not replace pins with arbitrary downloads or bypass verification.
