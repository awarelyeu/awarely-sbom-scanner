# Third-party notices

Awarely Scan currently imports only the Go standard library. It does not bundle Syft and has no third-party Go module dependencies.

Compiled binaries include Go runtime and standard-library code. The Go Authors' BSD license is reproduced in [licenses/GO-LICENSE.txt](licenses/GO-LICENSE.txt). Release packaging also includes the license and patent notices shipped with the pinned Go toolchain, including bundled standard-library vendor notices.

The Apache-2.0 license at the repository root covers Awarely Scan's own source. Third-party components keep their respective licenses. CI/build tools have their own licenses and are not part of the runtime binary.

## RPM database format reference

go-rpmdb format reference (https://github.com/knqyf263/go-rpmdb)
The bounded BDB reader was written using this MIT-licensed format reference.

MIT License

Copyright (c) 2019 Teppei Fukuda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Optional Syft

The guided scanner can download the original [Anchore Syft](https://github.com/anchore/syft) release after explicit approval. Syft is Apache-2.0 licensed and is not linked into or bundled with the Awarely binary. The unchanged upstream archive, including its license notices, remains in the private tool cache. Third-party dependencies retain their upstream notices.

## Temporary installation and update verifier

If an appropriate system GitHub CLI is unavailable, the installer offers to download the original [GitHub CLI](https://github.com/cli/cli) 2.102.0 archive after explicit consent. It verifies a maintainer-pinned SHA-256 before extraction and execution, keeps the upstream MIT license beside the temporary executable, and deletes the temporary files on exit. GitHub CLI is not bundled or linked into the scanner. It verifies Awarely build provenance before Awarely is executed. Bootstrap trust depends on obtaining and reviewing the authentic installer.

Explicit CLI updates also download this pinned GitHub CLI verifier into a private temporary directory, preserve its MIT license beside it, and remove it after verification. It is not linked into the Awarely binary. Managed Syft is pinned to 1.54.1 in this release.
