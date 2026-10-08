# Jenkins: from installation to your first inventory check

This guide covers preview 0.1.0-alpha.1. Start with a staging Jenkins controller and use the verified HPI from the [release guide](releases.md).

## 1. Prepare Jenkins once

You need Jenkins 2.580.1 or newer, a supported Jenkins Java runtime (JDK 21 for this plugin's tested baseline), and a Linux amd64 or arm64 agent running as a regular user. Keep the controller's executors at zero. Application builds may require Node.js/npm, Python or Maven/Java; the scanner itself does not require these runtimes for reading existing files.

Download the HPI from the [plugin releases](https://github.com/awarelyeu/awarely-sbom-scanner/releases) and follow [provenance and checksum verification](releases.md). Installing a plugin grants controller code execution.

Under **Manage Jenkins → Plugins → Available plugins**, install or update these dependencies: **Credentials**, **Plain Credentials**, **Branch API**, **SCM API**, **Structs**, **Jackson 2 API** and **Commons Compress API**. Jenkins resolves their dependencies too. For Jenkinsfiles, also install **Pipeline**. Review security warnings in **Manage Jenkins**.

Then open **Plugins → Advanced settings → Deploy Plugin**, select the verified HPI and upload it. Restart Jenkins when no builds are running. Confirm **Awarely Scan** appears under **Installed plugins**, without a loading error. The HPI is distributed here; this plugin is not yet listed in the Jenkins Update Center.

In **Manage Jenkins → System → Awarely Scan**:

1. Enable **Allow verified tool downloads** if agents may fetch the pinned CLI and Syft. This is permission to download the specific tested tools; it never selects an unreviewed latest version.
2. Enter the exact full names of jobs permitted to contact Monitor, one per line. For a folder or multibranch job, include its complete Jenkins job name. Wildcards are not supported.
3. Enter the exact agent node names trusted for remote operations. Run trusted builds on agents isolated from external pull requests and other untrusted jobs.
4. Copy the HTTPS API origin from your downloaded Monitor credential into **Allowed Monitor API origins**. An origin contains the scheme, hostname and optional port, without a path. Obtain it from your own trusted Monitor account.
5. Separately approve deployment jobs under **Jobs allowed to synchronize inventory**. Permission to check does not automatically authorize synchronization.
6. If you want Linux host inventory, separately approve the exact job under **Jobs allowed to inventory the agent host**.

A local application scan needs no Monitor account or credential. The tool cache lives outside the job workspace, under the agent root's `.awarely-scan` directory, with owner-only permissions. To operate without downloads, an administrator must populate the pinned release archive cache and the CLI's verified Syft cache in advance. An absent or modified archive stops the step.

## 2. Add a credential for checks

In Monitor, open **Settings → Assets → Awarely Scan CLI**. With Pro access and MFA, create a short-lived **Check only** credential for the intended application/source and download its JSON file.

In the appropriate Jenkins folder's credentials store, add a **Secret file**, upload that JSON and give it a recognizable ID, such as `awarely-monitor-check`. Restrict job configuration and credential access to the people who should be able to use that account. Do not commit the JSON to Git, paste its token into a Jenkinsfile or bind it as an environment variable.

The Awarely step reads the selected Secret file only when needed and passes it to the verified CLI through standard input. It never copies it into the workspace or archives it.

## 3. Run a first local scan

For a Freestyle project, choose **Add build step → Awarely Scan: inventory, check or synchronize**. Select a collector, a path relative to the workspace, an application label, and **Save local inventory only**. Build the application first if using Syft.

For Pipeline, use **Pipeline Syntax → Snippet Generator** to generate an `awarelyScan` step, or start with:

```groovy
pipeline {
  agent { label 'linux' }
  options {
    timeout(time: 15, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '20'))
    skipStagesAfterUnstable()
  }
  stages {
    stage('Inventory') {
      steps {
        awarelyScan collector: 'npm', mode: 'local',
          path: '.', applicationLabel: 'shop'
      }
    }
  }
}
```

The checked-out workspace must contain your application's lockfile. Replace example paths and labels with your own values. A native manifest scan does not need `npm install`; a Syft scan inspects installed or built artifacts, so run your usual dependency/build steps first.

Open the build's **Awarely Scan** page and its **Artifacts**. A fresh inventory is archived under `awarely/<run-id>/inventory.cdx.json`. Inventory files reveal software identities and versions; restrict build/artifact read access and choose appropriate retention.

## 4. Check CVEs and set a build policy

Change the step to:

```groovy
awarelyScan collector: 'npm', mode: 'check',
  path: '.', applicationLabel: 'shop',
  credentialsId: 'awarely-monitor-check',
  severityThreshold: 'HIGH', failOnIncomplete: true
```

`check` sends normalized package identities, versions and evidence to the configured Monitor API. It does not save inventory or change alerts. Jenkins archives the complete JSON result and shows a bounded preview with the assessment period, severity, precision and unevaluated count.

- `REPORT_ONLY`: report findings without a severity gate.
- `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`: mark the build **UNSTABLE** when a version-confirmed component match reaches that severity or higher.
- Product-only matches remain visible but do not satisfy a version-confirmed gate.
- `failOnIncomplete: true` also marks a partial inventory or unevaluated components **UNSTABLE**, independently of the number of matches.
- Invalid input, rejected credentials, API errors or tool-verification failures fail the step. They do not become a successful zero-CVE result.

Use Declarative Pipeline's `skipStagesAfterUnstable()` when an unstable assessment must prevent later deployment stages. `REPORT_ONLY` does not turn off the separate incomplete-coverage policy. A successful check describes the selected inventory and available catalog, not proof that the application is secure.

## 5. Python and Java

For an existing virtual environment inside the workspace:

```groovy
awarelyScan collector: 'python-syft', mode: 'check',
  path: 'services/reports', applicationLabel: 'reports',
  credentialsId: 'awarely-monitor-check', severityThreshold: 'HIGH'
```

Create the virtual environment and install the application's dependencies in an earlier build step. The `python` collector reads requirements.txt instead and reports partial coverage because transitive installed dependencies are unknown.

For Java:

```groovy
awarelyScan collector: 'java', mode: 'check',
  path: 'services/shipping', applicationLabel: 'shipping',
  credentialsId: 'awarely-monitor-check', severityThreshold: 'HIGH'
```

Build the JAR/WAR/EAR and include dependencies before scanning. Scanning an empty source directory is not equivalent to scanning the built application. Syft is managed by the pinned CLI release; there is no interactive prompt and no arbitrary Syft version setting.

## 6. Synchronize a deployed inventory

Use a dedicated **Sync only** credential and a trusted deployment job. Give each application/environment source one writer job. Synchronize the inventory that represents the deployed artifact, after the deployment succeeds; a build that merely compiles code should usually perform `check`.

```groovy
awarelyScan collector: 'java', mode: 'sync',
  path: 'services/shipping', applicationLabel: 'shipping-production',
  credentialsId: 'awarely-monitor-sync'
```

The application label describes the SBOM; the credential determines the destination application and source. Sync immediately replaces that source and preserves other sources. Partial and empty snapshots are refused. The plugin serializes its sync operations, persists a conservative build-order marker and rejects older builds or a different job writing the same source. The server also enforces revision and idempotency checks. External writers remain subject to server conflicts; keep one writer per source.

Do not wrap sync in a blind `retry` block. A timeout, controller restart or lost receipt can leave the commit outcome uncertain. Inspect the source in Monitor before retrying. The CLI keeps the same request revision and idempotency key for its own bounded transport retries. This plugin does not resume an interrupted process after a controller restart.

## 7. Read common outcomes

| Outcome | Meaning and next step |
| --- | --- |
| Directory missing | Correct the path relative to the workspace; check out/build the project first. Absolute paths and parent traversal are rejected. |
| Tool unavailable | Ask the administrator to allow verified downloads or prepare the documented pinned cache. |
| Job/agent/origin not approved | Ask the Jenkins administrator to approve the intended trusted job, agent and Monitor destination. |
| Partial Python inventory | Use `python-syft` after creating the virtual environment, or deliberately retain partial coverage. |
| Unevaluated ecosystem | Inventory exists, but that ecosystem has no implemented CVE assessment. Zero matches is not an all-clear. |
| Agent Linux packages | These describe the build agent. Use a scanner on the actual server for that server's inventory. |
| Source assigned to another job/newer build | Use the source's designated writer job. After job renames or build-number resets, an administrator must review the persisted binding rather than silently discard ordering protection. |
| Interrupted sync | Check the saved source in Monitor before retrying. |

## 8. Update and maintain

Update the Jenkins plugin deliberately from a verified release. Each plugin release fixes the CLI archive/executable digests; managed Syft follows that CLI. Ordinary builds do not run `update`, execute downloaded installers or replace the pinned version with `latest`. Test upgrades on a staging controller first.

Revoke or rotate Monitor credentials when jobs change ownership or scope. Retain only the build artifacts you need. Clean or recycle isolated agents if a build aborts during filesystem cleanup.

Checks are limited by the Monitor account’s API quota (currently six checks per minute, with bounded concurrency). Stagger parallel jobs; do not create additional credentials to bypass an account limit. A refused request fails visibly and preserves the local SBOM.
