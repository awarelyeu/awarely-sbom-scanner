"""Native, unprivileged offline CLI versus the distro's own RPM query oracle.

Images are test fixtures only. No inventory or credentials leave this test.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)
image = sys.argv[2]
if image not in [f"{d}:{v}" for d in ("rockylinux/rockylinux", "almalinux") for v in (8,9,10)]:
    raise SystemExit("Unexpected distro test image")
subprocess.run(["docker", "pull", image], check=True, timeout=180)
digest = subprocess.check_output(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image], text=True).strip()
print("Independent test fixture:", digest)
with tempfile.TemporaryDirectory(prefix="awarely-rpm-test-") as tmp:
    folder = Path(tmp)
    # Docker's tmpfs is writable by the unprivileged test user; the rootfs is not.
    base = ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534", "--tmpfs=/tmp:rw,nosuid,nodev,mode=1777", "--mount", f"type=bind,src={binary},dst=/awarely-scan,readonly", digest]
    oracle = subprocess.check_output(base + ["rpm", "-qa", "--queryformat", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"], text=True, timeout=30)
    expected = {tuple(line.split("\t")) for line in oracle.splitlines() if not line.startswith("gpg-pubkey\t")}
    assert expected and all(len(x)==3 for x in expected)
    # The shell belongs exclusively to the test harness, never to the collector.
    script = '/awarely-scan host --all-packages --output /tmp/all.json --name rpm-test && cat /tmp/all.json'
    result = subprocess.run(base + ["sh", "-c", script], text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    # CLI diagnostics are on stderr; only the file is returned by this harness.
    raw = result.stdout[result.stdout.index('{'):]
    bom = json.loads(raw)
    from urllib.parse import urlparse,parse_qs
    actual = {(c['name'],c['version'],parse_qs(c['purl'].partition('?')[2])['arch'][0]) for c in bom['components']}
    assert actual == expected, (sorted(expected-actual)[:10],sorted(actual-expected)[:10])
    assert all(c['purl'].startswith('pkg:rpm/') for c in bom['components'])
    for component in bom['components']:
        props = {p['name']:p['value'] for p in component['properties']}
        assert props['awarely:evidence']=='installed-rpm'
        assert props.get('awarely:rpm-vendor') and props.get('awarely:source-package')
    # Focused inventory must retain bash and its installed providers and must not
    # silently turn a malformed/missing selector into a complete empty snapshot.
    script='/awarely-scan host --select bash --output /tmp/focused.json --name rpm-test; rc=$?; cat /tmp/focused.json; exit "$rc"'
    result=subprocess.run(base+["sh","-c",script],text=True,capture_output=True,timeout=60)
    assert result.returncode==0,result.stderr
    focused=json.loads(result.stdout[result.stdout.index('{'):])
    assert any(c['name']=='bash' for c in focused['components'])
    assert len(focused['components'])<len(bom['components'])
    result = subprocess.run(base + ["/awarely-scan", "host", "--output", "/tmp/default.json", "--name", "rpm-test"], text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    print(f"PASS {image}: {len(actual)} exact RPM identities; focused closure {len(focused['components'])}; offline, non-root, read-only root")
