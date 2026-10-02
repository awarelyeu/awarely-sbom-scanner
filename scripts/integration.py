"""Exercise the built CLI on synthetic inputs; strace is mandatory on Linux."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="awarely-scan-test-") as folder:
    root = Path(folder)
    app = root / "app"
    app.mkdir()
    (app / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/demo": {"version": "1.2.3", "resolved": "https://token:PRIVATE_CANARY@example.invalid/a"}},
    }))
    marker = root / "MUST_NOT_EXIST"
    (app / "package.json").write_text(json.dumps({"scripts": {"preinstall": f"touch {marker}"}}))
    (app / ".env").write_text("FAKE_SECRET=PRIVATE_CANARY")
    output = root / "app.cdx.json"
    command = [str(binary), "app", "--path", str(app), "--output", str(output), "--name", "synthetic-app"]
    trace = root / "syscalls.txt"
    if sys.platform == "linux":
        assert shutil.which("strace"), "Install strace for the Linux integration gate"
        command = ["strace", "-f", "-e", "trace=network,execve", "-o", str(trace)] + command
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, env={"PATH": os.environ["PATH"], "HOME": str(root)})
    assert result.returncode == 0, result.stderr
    report = output.read_text()
    assert "PRIVATE_CANARY" not in report + result.stdout + result.stderr
    assert not marker.exists()
    assert (output.stat().st_mode & 0o777) == 0o600
    bom = json.loads(report)
    assert bom["bomFormat"] == "CycloneDX" and len(bom["components"]) == 1
    if trace.exists():
        calls = trace.read_text()
        assert len(re.findall(r"\bexecve\(", calls)) == 1, "unexpected child execution"
        assert not re.search(r"\b(socket|connect|sendto|sendmsg|bind|listen|accept|recvfrom|recvmsg)\(", calls), calls
    before = output.read_bytes()
    result = subprocess.run([str(binary), "app", "--path", str(app), "--output", str(output)], capture_output=True, timeout=20)
    assert result.returncode == 4 and output.read_bytes() == before
    for mode in ["check", "sync"]:
        assert subprocess.run([str(binary), mode], capture_output=True, timeout=5).returncode == 2
    # Exercise the product limit without truncating or turning partial input into success.
    packages = {f"node_modules/pkg-{i}": {"version": "1.2.3"} for i in range(5000)}
    (app / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    large = root / "large.cdx.json"
    result = subprocess.run([str(binary), "app", "--path", str(app), "--output", str(large)], capture_output=True, timeout=15)
    assert result.returncode == 0 and len(json.loads(large.read_text())["components"]) == 5000, result.stderr
    packages["node_modules/over-limit"] = {"version": "1.2.3"}
    (app / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    over = root / "over-limit.cdx.json"
    result = subprocess.run([str(binary), "app", "--path", str(app), "--output", str(over)], capture_output=True, timeout=15)
    assert result.returncode == 2 and not over.exists(), result.stderr
    print("PASS: 5,000 components exported; over-limit input rejected without publication")
    print("PASS: local export, privacy, no script execution, no overwrite, remote modes require explicit arguments")
    if trace.exists():
        print("PASS: Linux syscall trace contains zero network calls and zero child processes")
        host_output = root / "host.cdx.json"
        result = subprocess.run([str(binary), "host", "--select", "bash", "--output", str(host_output)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        host = json.loads(host_output.read_text())
        assert any(c["name"] == "bash" and "distro=ubuntu-" in c["purl"] for c in host["components"])
        print("PASS: native Ubuntu installed-package inventory and dependency closure")
