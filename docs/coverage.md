# Coverage and limits

## Application profile

Read these fixed filenames directly under `--path`, without walking the tree:

1. `npm-shrinkwrap.json`, otherwise `package-lock.json`, otherwise `package.json`.
2. `requirements.txt`, when present.

npm lockfiles must use version 2 or 3. All represented non-link package entries are included, including development and optional entries; existence in the lockfile is not proof of installation. The collector preserves npm scopes and actual alias names when supplied in lock metadata. Workspace links/local workspace entries are not followed and make coverage partial.

`package.json` and `requirements.txt` cannot establish the complete resolved dependency tree. They always yield partial coverage. Exact declarations are labeled declared, not installed. Version ranges do not become an exact version in the SBOM. Python environment markers are not evaluated and their declarations are included conservatively with a warning. Includes, direct references and continuations are not followed.

This preview does not support Alpine, pnpm/yarn/poetry locks, language environments, arbitrary binaries, JAR/ZIP/OCI archives, containers or automatic monorepo discovery. Select individual application directories with supported files.

## Host profile

Debian, Ubuntu, Rocky Linux, AlmaLinux and Amazon Linux are auto-detected using `ID` and `VERSION_ID` in regular `etc/os-release` or `usr/lib/os-release` files. For Debian/Ubuntu, installed-package metadata is read from `var/lib/dpkg/status`. The default profile selects:

```text
nginx*,apache2*,openssl,openssh-server,nodejs,python3,php*,openjdk-*,
postgresql*,mysql-server*,mariadb-server*,redis-server,docker.io,containerd,runc
```

Installed dependencies reachable through `Depends` and `Pre-Depends` are included. For alternative dependencies/virtual providers, all matching installed providers are included conservatively. Architecture qualifiers/version predicates are not a dependency solver; the output reflects installed database records. Missing providers produce a warning. Suggested/recommended packages are outside this focused closure.

Use `--select 'name,prefix*'` to override the selection, or `--all-packages` for every installed package record. An unmatched custom selector makes the report partial; absent members of the default optional server profile do not. Unmanaged software, running-process state, kernel live-patch state and deployment completeness are outside this profile. A missing selected package does not prove the corresponding software is absent outside its package database.

Distro/release, architecture and full version epoch/revision are kept in package URLs. No vulnerability matching is done locally.

### Rocky Linux and AlmaLinux

The same Linux amd64/arm64 binaries read RPM SQLite databases (including committed WAL frames) or Berkeley DB hash databases under the documented RPM database locations. No `rpm`, `dnf`, database engine, shell or package scripts are executed. Changed snapshots and active rollback journals fail with a retry instruction. The selected root is never modified.

The RPM default profile is:

```text
nginx*,httpd*,openssl,openssh-server,nodejs*,python3*,php*,java-*-openjdk*,
postgresql*,mysql-server*,mariadb-server*,redis*,docker-ce,containerd.io,runc,podman
```

Installed providers for required capabilities and file paths are included conservatively. Missing providers and unsupported rich dependency expressions make collection partial. This is an inventory of installed records, not a dependency solver. Unmanaged software and running kernel/livepatch state are outside scope. NDB and encrypted or custom database formats are not supported.

RPM PURLs retain distribution release, architecture and full epoch/version/release. Source RPM name/version, installed vendor and module label are metadata properties. These values are claims from the package database, not cryptographic attestation. Advisory checks use the binary RPM EVR and the matching module stream, not the source RPM version or upstream SemVer.

## Bounds and failure behavior

| Resource | Limit |
| --- | --- |
| Manifest | 5 MiB each |
| dpkg status | 64 MiB / 50,000 records |
| RPM database / WAL / header | 128 MiB / 64 MiB / 32 MiB |
| RPM records / retained header array | 50,000 / 262,144 entries |
| Expanded RPM metadata, per package / total | 32 MiB / 64 MiB |
| Retained RPM capabilities / dependency work steps | 250,000 / 2,000,000 |
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

Rocky Linux and AlmaLinux checks cover 8/9/10 on x86_64/aarch64, plus noarch packages. Only recognized distribution vendors, binary package identities and module streams are assessed. Third-party rebuilds, EPEL, specialized channels, unsupported architectures and packages absent from the catalog remain unevaluated. RPM checks use published security errata and therefore do not claim coverage for every issue without a published fix.

### Amazon Linux

The same RPM reader supports Amazon Linux 2023 and Amazon Linux 2, including SQLite/WAL and Berkeley DB databases. `ID=amzn` is required; `ID_LIKE` never substitutes for the actual distribution.

Amazon Linux 2023 checks use official core-repository ALAS advisories with exact package name, architecture and RPM EVR. Updating a pinned release may require selecting a newer repository release. Amazon Linux 2 is end-of-life: inventory and sync work, but checks return an explicit end-of-life assessment gap. Neither an unevaluated package nor an empty match list certifies safety.

References: [ALAS metadata](https://docs.aws.amazon.com/linux/al2023/ug/alas.html), [AL2023 support](https://docs.aws.amazon.com/linux/al2023/ug/release-cadence.html), [AL2 end of life](https://docs.aws.amazon.com/AL2/latest/relnotes/relnotes-20260825.html).
