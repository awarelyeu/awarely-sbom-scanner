"""Build deterministic release archives from an explicit version and revision."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

version = sys.argv[1]
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", version):
    raise SystemExit("Invalid release version")
source = Path(__file__).resolve().parents[1]
os.chdir(source)
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], text=True))
go_version = subprocess.check_output(["go", "env", "GOVERSION"], text=True).strip()
if go_version != "go1.27.1":
    raise SystemExit("Release toolchain must be go1.27.1")
goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
dest = source / "dist"
dest.mkdir(exist_ok=True)
notices = {"licenses/GO-LICENSE.txt": (goroot / "LICENSE").read_bytes()}
for name in ["PATENTS"]:
    if (goroot / name).is_file(): notices["licenses/GO-" + name + ".txt"] = (goroot / name).read_bytes()
for path in sorted((goroot / "src").rglob("LICENSE")):
    if "testdata" not in path.parts:
        notices["licenses/go-" + str(path.relative_to(goroot / "src")).replace("/", "_") + ".txt"] = path.read_bytes()
archives = []
for arch in ["amd64", "arm64"]:
    binary = dest / ("awarely-scan_linux_" + arch)
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch, "GOTOOLCHAIN": "local"}
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", f"-s -w -X main.version={version}", "-o", str(binary), "./cmd/awarely-scan"], env=env, check=True)
    content = binary.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "awarely-scan", "version": version,
                                      "hashes": [{"alg": "SHA-256", "content": digest}]},
                         "properties": [{"name": "awarely:source-revision", "value": revision},
                                        {"name": "awarely:target", "value": "linux/" + arch},
                                        {"name": "awarely:third-party-go-modules", "value": "none"}]},
            "components": [{"type": "framework", "name": "Go runtime and standard library", "version": go_version.removeprefix("go"),
                            "purl": "pkg:golang/stdlib@" + go_version.removeprefix("go"),
                            "properties": [{"name": "awarely:coverage", "value": "aggregate toolchain component; bundled notices included"}]}],
            "compositions": [{"aggregate": "incomplete"}]}
    members = {"awarely-scan": content, "binary-sbom.cdx.json": (json.dumps(sbom, indent=2) + "\n").encode(),
               "SHA256SUMS": (digest + "  awarely-scan\n").encode(), **notices}
    for name in ["LICENSE", "NOTICE", "README.md", "SECURITY.md", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md", "docs/coverage.md", "docs/releases.md", "docs/roadmap.md"]:
        members[name] = (source / name).read_bytes()
    archive = dest / f"awarely-scan_{version}_linux_{arch}.tar.gz"
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == "awarely-scan" else 0o644
            info.mtime = epoch
            tar.addfile(info, io.BytesIO(data))
    archives.append(archive)
    print(f"Built {archive.name} ({archive.stat().st_size} bytes)")
(dest / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in archives))
