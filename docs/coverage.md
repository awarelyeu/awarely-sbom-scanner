# Coverage and limits

## Application profile

Read these fixed filenames directly under `--path`, without walking the tree:

1. `npm-shrinkwrap.json`, otherwise `package-lock.json`, otherwise `package.json`.
2. `requirements.txt`, when present.

npm lockfiles must use version 2 or 3. All represented non-link package entries are included, including development and optional entries; existence in the lockfile is not proof of installation. The collector preserves npm scopes and actual alias names when supplied in lock metadata. Workspace links/local workspace entries are not followed and make coverage partial.

`package.json` and `requirements.txt` cannot establish the complete resolved dependency tree. They always yield partial coverage. Exact declarations are labeled declared, not installed. Version ranges do not become an exact version in the SBOM. Python environment markers are not evaluated and their declarations are included conservatively with a warning. Includes, direct references and continuations are not followed.

This preview does not support RPM, Alpine, pnpm/yarn/poetry locks, language environments, arbitrary binaries, JAR/ZIP/OCI archives, containers or automatic monorepo discovery. Select individual application directories with supported files.

## Host profile

Only Debian or Ubuntu with `ID` and `VERSION_ID` in regular `etc/os-release` or `usr/lib/os-release` files is supported. Installed-package metadata is read from `var/lib/dpkg/status`. The default profile selects:

```text
nginx*,apache2*,openssl,openssh-server,nodejs,python3,php*,openjdk-*,
postgresql*,mysql-server*,mariadb-server*,redis-server,docker.io,containerd,runc
```

Installed dependencies reachable through `Depends` and `Pre-Depends` are included. For alternative dependencies/virtual providers, all matching installed providers are included conservatively. Architecture qualifiers/version predicates are not a dependency solver; the output reflects installed database records. Missing providers produce a warning. Suggested/recommended packages are outside this focused closure.

Use `--select 'name,prefix*'` to override the selection, or `--all-packages` for every installed DEB record. An unmatched custom selector makes the report partial; absent members of the default optional server profile do not. Unmanaged software, running-process state, kernel live-patch state and deployment completeness are outside this profile. A missing selected package does not prove the corresponding software is absent outside dpkg.

Distro/release, architecture and full version epoch/revision are kept in package URLs. No vulnerability matching is done locally.

## Bounds and failure behavior

| Resource | Limit |
| --- | --- |
| Manifest | 5 MiB each |
| dpkg status | 64 MiB / 50,000 records |
| os-release | 64 KiB |
| JSON nesting | 16 |
| JSON values | 150,000 |
| JSON member name / string | 1 KiB / 16 KiB |
| Text line / dpkg retained field | 64 KiB |
| Unique components | 5,000 |
| Serialized output | 5 MiB |
| Application name | 120 bytes, no control/format characters |
| Deadline | 60 seconds by default, maximum 300 |

Over-limit and invalid input fail without a new final report. A supported but incomplete scope can produce a report with exit 3. No component list is silently truncated. Existing output is preserved even if publication fails.

`awarely:coverage=complete-for-selected-inputs` means the supported selected inputs were processed without known omissions. It never means that a host is fully inventoried or free of vulnerabilities. CycloneDX composition remains `incomplete` to avoid asserting more.

## Distribution vulnerability checks

`host` preserves the dpkg `Source` field. If it omits the source version, the binary version applies; if the field is absent, the package name and version apply. This preserves the original source version for binary-only rebuilds. These values are included as `awarely:source-package` and `awarely:source-version` properties.

`check` evaluates supported Debian/Ubuntu releases using their official advisory data and Debian version ordering. It includes older advisories still applicable to installed packages. A fix supplied through Ubuntu Pro may require a subscription to obtain; the report does not infer subscription status. See the support and uncertainty boundaries in the [README](../README.md).
