"""Check the local collector's dependency boundary; no project files executed."""
import os
import subprocess

# Inspect the actual static release configuration. Race tests intentionally
# enable cgo on Linux; that configuration is never packaged for users.
release_env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOTOOLCHAIN": "local"}

packages = subprocess.check_output(
    ["go", "list", "-deps", "./internal/inventory", "./internal/safeio"], text=True, env=release_env
).splitlines()
forbidden = {"net", "net/http", "net/rpc", "os/exec", "plugin", "runtime/cgo"}
assert not forbidden.intersection(packages), sorted(forbidden.intersection(packages))
external = subprocess.check_output(
    ["go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./cmd/awarely-scan"],
    text=True, env=release_env,
).splitlines()
assert all(not p or p.startswith("github.com/awarelyeu/awarely-sbom-scanner/") for p in external)
for arch in ["amd64", "arm64"]:
    runtime_packages = subprocess.check_output(
        ["go", "list", "-deps", "./cmd/awarely-scan"], text=True,
        env={**release_env, "GOARCH": arch},
    ).splitlines()
    unexpected = {"plugin", "runtime/cgo"}.intersection(runtime_packages)
    assert not unexpected, (arch, sorted(unexpected))
print("PASS: offline collector has no network dependency; native collector has no subprocess; executable has no external modules, plugin or cgo")

# Only the consented producer boundary may launch a child process.
from pathlib import Path
for source in Path(".").glob("**/*.go"):
    if not source.name.endswith("_test.go") and "/producer/" not in source.as_posix():
        assert '"os/exec"' not in source.read_text(), source
