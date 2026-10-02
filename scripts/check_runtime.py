"""Check the local collector's dependency boundary; no project files executed."""
import subprocess

packages = subprocess.check_output(
    ["go", "list", "-deps", "./cmd/awarely-scan"], text=True
).splitlines()
forbidden = {"net", "net/http", "net/rpc", "os/exec", "plugin", "runtime/cgo"}
assert not forbidden.intersection(packages), sorted(forbidden.intersection(packages))
external = subprocess.check_output(
    ["go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./cmd/awarely-scan"],
    text=True,
).splitlines()
assert all(not p or p.startswith("github.com/awarelyeu/awarely-sbom-scanner/") for p in external)
print("PASS: no external modules, network client, subprocess or cgo runtime dependency")
