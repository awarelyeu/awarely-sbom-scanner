"""Package only reviewed plugin release outputs; refuse mismatched tags or unfinished pins."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import xml.etree.ElementTree as ET
import zipfile

root = Path(__file__).resolve().parents[1]
version = ET.parse(root / 'pom.xml').getroot().find('{http://maven.apache.org/POM/4.0.0}version').text
tag = sys.argv[1]
if not re.fullmatch(r'jenkins-v\d+\.\d+\.\d+(?:-alpha\.\d+)?', tag) or tag != 'jenkins-v' + version:
    raise SystemExit('Tag must match the explicit non-SNAPSHOT plugin version')
pins = dict(line.split('=', 1) for line in (root / 'src/main/resources/io/jenkins/plugins/awarely/tools.properties').read_text().splitlines() if line and not line.startswith('#'))
for arch in ('amd64', 'arm64'):
    for kind in ('archive', 'binary'):
        if not re.fullmatch(r'[0-9a-f]{64}', pins.get(arch + '.' + kind, '')):
            raise SystemExit('Unfinished tool pins cannot be released')
hpi = root / 'target/awarely-scan.hpi'
with zipfile.ZipFile(hpi) as archive:
    manifest = archive.read('META-INF/MANIFEST.MF').decode().replace('\r\n ', '').replace('\r\n', '\n')
    if 'Plugin-Version: ' + version + '\n' not in manifest:
        raise SystemExit('Packaged plugin version does not match tag')
bom = root / 'target/bom.json'
if json.loads(bom.read_text()).get('bomFormat') != 'CycloneDX':
    raise SystemExit('Missing CycloneDX dependency inventory')
dest = root.parent / 'dist/jenkins'
dest.mkdir(parents=True, exist_ok=False)
shutil.copyfile(hpi, dest / f'awarely-scan-jenkins-{version}.hpi')
shutil.copyfile(bom, dest / f'awarely-scan-jenkins-{version}.cdx.json')
(dest / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(dest.iterdir())))
print('Packaged plugin and dependency inventory for ' + tag)
