# Third-party notices

Awarely Scan currently imports only the Go standard library. It does not bundle Syft and has no third-party Go module dependencies.

Compiled binaries include Go runtime and standard-library code. The Go Authors' BSD license is reproduced in [licenses/GO-LICENSE.txt](licenses/GO-LICENSE.txt). Release packaging also includes the license and patent notices shipped with the pinned Go toolchain, including bundled standard-library vendor notices.

The Apache-2.0 license at the repository root covers Awarely Scan's own source. Third-party components keep their respective licenses. CI/build tools have their own licenses and are not part of the runtime binary.
