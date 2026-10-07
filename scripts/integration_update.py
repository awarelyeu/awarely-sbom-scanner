"""Built update/rollback filesystem contract; synthetic version labels, no network.

Archive authentication is covered by unit trust-gate tests and release E2E.
This checks the second stage invoked only after the installer verifies an archive.
"""
import hashlib, os, shutil, subprocess, tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix='awarely-update-test-', dir=Path.home()) as directory:
    root = Path(directory)
    candidate = root/'candidate'
    old = root/'old'
    for dest, version in [(old, 'v0.8.0-alpha.2'), (candidate, 'v0.9.0-alpha.1')]:
        subprocess.run(['go', 'build', '-trimpath', '-ldflags', '-X main.version='+version,
                        '-o', str(dest), './cmd/awarely-scan'], check=True)
    home = root/'home'
    dest = home/'.local/bin/awarely-scan'
    dest.parent.mkdir(parents=True, mode=0o700)
    shutil.copyfile(old, dest)
    dest.chmod(0o700)
    old_digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    env = {**os.environ, 'HOME': str(home), 'GH_TOKEN': 'synthetic-do-not-use'}
    def run(binary, args, answer='', code=0):
        p = subprocess.run([str(binary), *args], input=answer, text=True,
                           capture_output=True, env=env, timeout=30)
        assert p.returncode == code, (p.returncode, p.stdout, p.stderr)
        return p.stdout
    run(candidate, ['install'], 'no\n')
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == old_digest
    run(candidate, ['install'], 'yes\n')
    assert 'v0.9.0-alpha.1' in run(dest, ['version'])
    assert 'Managed Syft:' in run(dest, ['version', '--tools'])
    state = dest.parent/'.awarely-scan-update'
    records = list(state.glob('*.json'))
    assert len(records) == 1 and records[0].stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o700
    assert dest.stat().st_mode & 0o777 == 0o700
    run(candidate, ['install'], 'yes\n', code=7)  # same version is not an upgrade
    run(old, ['install'], 'yes\n', code=7)  # never downgrade through installer
    run(dest, ['update', '--rollback'], 'no\n')
    assert 'v0.9.0-alpha.1' in run(dest, ['version'])
    run(dest, ['update', '--rollback'], 'yes\n')
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == old_digest
    run(dest, ['update', '--rollback'], 'yes\n', code=7)  # no unrelated backup
    assert not list(dest.parent.glob('.awarely-stage-*'))
    assert not list(state.glob('probe-*')) and not list(state.glob('install-*'))
    print('PASS: built CLI consent, atomic upgrade, private backup, exact rollback, no downgrade, temporary cleanup')
