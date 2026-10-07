"""Test-only pinned Syft interoperability on Linux amd64/arm64; never shipped."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

VERSION = '1.54.1'
# Verified against Anchore's Sigstore-signed release checksums before pinning.
HASHES = {
    'x86_64': ('amd64', 'c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47'),
    'aarch64': ('arm64', 'dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054'),
}
binary = Path(sys.argv[1]).resolve(strict=True)
arch, digest = HASHES[platform.machine()]
with tempfile.TemporaryDirectory(prefix='awarely-syft-test-') as directory:
    root = Path(directory)
    url = f'https://github.com/anchore/syft/releases/download/v{VERSION}/syft_{VERSION}_linux_{arch}.tar.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        assert response.url.startswith('https://')
        archive = response.read(100 * 1024 * 1024)
    assert hashlib.sha256(archive).hexdigest() == digest
    syft = root / 'syft'
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        entry = tar.getmember('syft')
        assert entry.isfile() and entry.size < 200 * 1024 * 1024
        syft.write_bytes(tar.extractfile(entry).read())
    syft.chmod(0o700)
    app = root / 'app'
    shutil.copytree(Path(__file__).resolve().parents[1] / 'tests/fixtures/syft', app)
    with zipfile.ZipFile(app / 'demo.jar', 'w') as jar:
        jar.writestr('META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties', 'groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n')
        jar.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nImplementation-Version: 2.14.1\n')
    config = root / 'offline.yaml'
    config.write_text('''check-for-app-update: false
enrich: []
java:
  use-network: false
  use-maven-local-repository: false
golang:
  use-packages-lib: false
  search-remote-licenses: false
javascript:
  search-remote-licenses: false
python:
  search-remote-licenses: false
cpp:
  vcpkg-allow-git-clone: false
''')
    raw = root / 'syft.json'
    # The CI runner invokes Syft as its ordinary user in a network namespace.
    # The test harness alone uses sudo to create that namespace, then drops UID.
    command = ['sudo', 'unshare', '--net', '--setuid', str(os.getuid()), '--setgid', str(os.getgid()), '--',
               'env', '-i', 'PATH=/usr/bin:/bin', 'HOME=' + str(root), str(syft), 'scan', 'dir:' + str(app),
               '--config', str(config), '--source-name', 'demo', '--source-version', '1.0.0',
               '--select-catalogers', 'java,javascript,python,dotnet,go,php,ruby,rust', '-o', 'cyclonedx-json=' + str(raw)]
    subprocess.run(command, check=True, timeout=180, capture_output=True)
    output = root / 'awarely.json'
    trace = root / 'trace.txt'
    subprocess.run(['strace', '-f', '-e', 'trace=network,execve', '-o', str(trace), str(binary),
                    'import', '--input', str(raw), '--output', str(output)], check=True, capture_output=True, timeout=30)
    calls = trace.read_text()
    assert len(re.findall(r'\bexecve\(', calls)) == 1
    assert not re.search(r'\b(socket|connect|sendto|sendmsg|bind|listen|accept|recvfrom|recvmsg)\(', calls)
    bom = json.loads(output.read_text())
    assert {c['purl'].split('/')[0] for c in bom['components']} == {
        'pkg:maven', 'pkg:npm', 'pkg:pypi', 'pkg:nuget', 'pkg:golang', 'pkg:composer', 'pkg:gem', 'pkg:cargo'}
    assert any(c['purl'] == 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' for c in bom['components'])
    assert str(root) not in output.read_text()
    assert output.stat().st_mode & 0o777 == 0o600
    print(f'PASS: Syft {VERSION} Linux {arch}, eight ecosystems; offline collection and private validated import')
