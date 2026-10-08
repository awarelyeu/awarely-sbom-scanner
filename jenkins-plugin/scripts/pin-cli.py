"""Authenticate both CLI archives before writing or checking the plugin's fixed tool pins."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'src/main/resources/io/jenkins/plugins/awarely/tools.properties'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--version', help='Exact published CLI tag (required when changing pins)')
p.add_argument('--check', action='store_true', help='Verify current pins without modifying files')
args = p.parse_args()
current = dict(line.split('=', 1) for line in MANIFEST.read_text().splitlines() if line and not line.startswith('#'))
version = args.version or current['version']
if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-alpha\.\d+)?', version):
    raise SystemExit('Invalid exact CLI tag')
if not args.check and not args.version:
    raise SystemExit('Changing pins requires --version TAG')
pins = {'version': version}
with tempfile.TemporaryDirectory(prefix='awarely-pin-') as work:
    work = Path(work)
    home = work / 'home'
    home.mkdir(mode=0o700)
    env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'LANG': 'C.UTF-8', 'GH_CONFIG_DIR': str(home / 'gh')}
    for arch in ('amd64', 'arm64'):
        name = f'awarely-scan_{version}_linux_{arch}.tar.gz'
        for filename, limit in ((name, 40 * 1024 * 1024), (name + '.sigstore.jsonl', 2 * 1024 * 1024)):
            subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                '--proto-redir', '=https', '--tlsv1.2', '--max-time', '180', '--max-filesize', str(limit),
                f'https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/{version}/{filename}',
                '--output', str(work / filename)], check=True, env=env)
        subprocess.run(['gh', 'attestation', 'verify', str(work / name), '--bundle', str(work / (name + '.sigstore.jsonl')),
            '--repo', 'awarelyeu/awarely-sbom-scanner', '--signer-workflow',
            'awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml', '--source-ref', f'refs/tags/{version}',
            '--deny-self-hosted-runners'], check=True, env=env)
        archive = work / name
        pins[arch + '.archive'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        found = False
        total = 0
        with tarfile.open(archive, 'r|gz') as tar:
            for count, entry in enumerate(tar, 1):
                total += entry.size
                if entry.size < 0 or total > 100 * 1024 * 1024 or count > 200:
                    raise SystemExit('Archive exceeds bounds')
                if entry.name != 'awarely-scan':
                    continue
                if found or not entry.isfile() or entry.size > 40 * 1024 * 1024:
                    raise SystemExit('Invalid executable entry')
                found = True
                binary = tar.extractfile(entry).read(40 * 1024 * 1024 + 1)
                if len(binary) != entry.size:
                    raise SystemExit('Invalid executable size')
                pins[arch + '.binary'] = hashlib.sha256(binary).hexdigest()
        if not found:
            raise SystemExit('Missing executable')
if args.check:
    if current != pins:
        raise SystemExit('Tool pins differ from the authenticated release')
    print('PASS: both CLI archives and executable pins match authenticated release provenance')
else:
    MANIFEST.write_text('# Authenticated with jenkins-plugin/scripts/pin-cli.py; never edit digests by hand.\n' +
                        ''.join(f'{k}={v}\n' for k, v in pins.items()))
    print('Updated fixed CLI pins after verifying both public provenance bundles')
