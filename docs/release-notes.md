# Installation without a system GitHub CLI

The installer can prepare a temporary pinned GitHub CLI verifier when gh is missing or too old, after explicit consent. It checks the upstream archive digest before execution and still requires signed provenance for the exact Awarely release. No GitHub account, root access or repository setup is needed for the verifier; temporary files are removed afterward.

Missing basic tools now show distribution-specific guidance and can be rechecked without restarting. Guided scans can explicitly retry temporary Syft download failures while keeping the selected directory. Integrity and unsafe-cache errors still stop.

The English and Romanian guides distinguish installation tools from scanner requirements. The scanner itself does not require gh. This remains a prerelease; ecosystem CVE coverage is unchanged.
