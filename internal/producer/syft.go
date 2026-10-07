// Package producer contains the optional, explicitly approved Syft runner.
// Native inventory collection never imports this package.
package producer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

const Version = "1.54.0"
const maxArchive = 40 << 20
const maxExecutable = 200 << 20

// Only transport/availability failures are eligible for an explicit retry.
// Integrity, cache permissions and size-limit errors remain fatal.
var ErrDownloadUnavailable = errors.New("Syft download unavailable; check HTTPS access to GitHub and retry")

// Maintainer-verified against the upstream Sigstore-signed checksum list.
// Trust in these pins comes from the verified Awarely release containing them.
var digests = map[string]string{
	"amd64": "54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860",
	"arm64": "ee6d4566373a05b344bc6b5f1706f14419bf9338ba39ff686e247deefe9b8818",
}

const offlineConfig = `check-for-app-update: false
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
`

func Supported() bool { return runtime.GOOS == "linux" && digests[runtime.GOARCH] != "" }

func privateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("cannot create private tool cache")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("cannot inspect tool cache")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || int(stat.Uid) != os.Geteuid() {
		return errors.New("tool cache must be an owner-only directory, not a symlink")
	}
	return nil
}

func archiveName() string { return "syft_" + Version + "_linux_" + runtime.GOARCH + ".tar.gz" }

// CachePath is not a search for executables: only this version's pinned archive
// is eligible. PATH, user Syft configuration and credential files are ignored.
func CachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("a valid home directory is required")
	}
	return filepath.Join(home, ".awarely-scan-tools"), nil
}

func readArchive(ctx context.Context, cache string) ([]byte, error) {
	if err := privateDirectory(cache); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(cache)
	if err != nil {
		return nil, errors.New("cannot open tool cache")
	}
	defer root.Close()
	data, err := safeio.ReadPrivateRegular(ctx, root, archiveName(), maxArchive)
	if err != nil {
		return nil, err
	}
	if !validDigest(data, digests[runtime.GOARCH]) {
		return nil, errors.New("cached Syft archive failed verification; remove that archive and retry")
	}
	return data, nil
}

func Cached(ctx context.Context, cache string) (bool, error) {
	_, err := readArchive(ctx, cache)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func validDigest(data []byte, expected string) bool {
	sum := sha256.Sum256(data)
	return expected != "" && hex.EncodeToString(sum[:]) == expected
}

func allowedDownload(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	switch u.Host {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

func download(ctx context.Context, client *http.Client, address, digest string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil || !allowedDownload(req.URL) {
		return nil, errors.New("unsupported tool download URL")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrDownloadUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, ErrDownloadUnavailable
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxArchive {
		return nil, errors.New("Syft download rejected or exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil || len(data) > maxArchive {
		return nil, errors.New("Syft download is incomplete or exceeds size limit")
	}
	if !validDigest(data, digest) {
		return nil, errors.New("Syft archive failed verification; nothing will be executed")
	}
	return data, nil
}

// Prepare may download only after its caller has obtained explicit permission.
// It never installs packages, modifies PATH or requests elevated privileges.
func Prepare(ctx context.Context, cache string, allowDownload bool) error {
	if !Supported() {
		return errors.New("managed Syft requires Linux amd64 or arm64")
	}
	if os.Geteuid() == 0 {
		return errors.New("run managed Syft as a regular user, without sudo")
	}
	if _, err := readArchive(ctx, cache); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("Syft cache is unsafe or failed verification; inspect the private cache before retrying")
	}
	if !allowDownload {
		return errors.New("Syft is not cached; download was not approved")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 180 * time.Second, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 || !allowedDownload(req.URL) {
			return errors.New("download redirect rejected")
		}
		return nil
	}}
	data, err := download(ctx, client, "https://github.com/anchore/syft/releases/download/v"+Version+"/"+archiveName(), digests[runtime.GOARCH])
	if err != nil {
		return err
	}
	if err := safeio.WriteNew(filepath.Join(cache, archiveName()), data); err != nil {
		// A concurrent approved process may have published the identical archive.
		if _, e := readArchive(ctx, cache); e != nil {
			return errors.New("cannot save verified Syft archive")
		}
	}
	return nil
}

func extract(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid Syft archive")
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxExecutable+10<<20))
	for {
		h, err := tr.Next()
		if err != nil {
			return errors.New("Syft executable is missing or archive is invalid")
		}
		if h.Name != "syft" {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > maxExecutable {
			return errors.New("unsafe Syft executable entry")
		}
		f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			return errors.New("cannot create isolated Syft executable")
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("cannot extract complete Syft executable")
		}
		return nil
	}
}

type boundedWriter struct {
	w         io.Writer
	remaining int
	cancel    context.CancelFunc
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		w.cancel()
		return 0, errors.New("producer output limit exceeded")
	}
	n, err := w.w.Write(p)
	w.remaining -= n
	return n, err
}

// Scan executes a digest-verified producer with a fixed configuration and empty
// credential environment. Configuration is not an OS sandbox; untrusted trees
// still require the caller's resource and filesystem isolation.
func Scan(parent context.Context, cache, target, kind string) (inventory.Result, error) {
	var r inventory.Result
	if !Supported() || os.Geteuid() == 0 {
		return r, errors.New("managed Syft requires a regular Linux user on amd64/arm64")
	}
	catalogers := map[string]string{"java": "java", "python": "python", "npm": "javascript", "other": "dotnet,go,php,ruby,rust"}[kind]
	if catalogers == "" {
		return r, errors.New("unsupported producer selection")
	}
	path, err := filepath.EvalSymlinks(target)
	if err == nil {
		path, err = filepath.Abs(path)
	}
	if err != nil {
		return r, errors.New("invalid selected directory")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || filepath.Clean(path) == "/" {
		return r, errors.New("select a readable application directory, not the host root")
	}
	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()
	data, err := readArchive(ctx, cache)
	if err != nil {
		return r, errors.New("Syft archive is missing or failed verification")
	}
	work, err := os.MkdirTemp(cache, "run-")
	if err != nil {
		return r, errors.New("cannot create private producer workspace")
	}
	defer os.RemoveAll(work)
	executable := filepath.Join(work, "syft")
	if err := extract(data, executable); err != nil {
		return r, err
	}
	config := filepath.Join(work, "offline.yaml")
	if err := safeio.WriteNew(config, []byte(offlineConfig)); err != nil {
		return r, err
	}
	raw := filepath.Join(work, "inventory.json")
	output, err := os.OpenFile(raw, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return r, errors.New("cannot create private producer output")
	}
	cmd := exec.CommandContext(ctx, executable, "scan", "dir:"+path, "--config", config, "--source-name", "application", "--source-version", "1.0.0", "--select-catalogers", catalogers, "-o", "cyclonedx-json")
	cmd.Dir = work
	cmd.Env = []string{"HOME=" + work, "XDG_CONFIG_HOME=" + work, "XDG_CACHE_HOME=" + work, "TMPDIR=" + work, "PATH=" + filepath.Join(work, "no-executables"), "LANG=C", "LC_ALL=C"}
	cmd.Stdout = &boundedWriter{output, inventory.MaxManifestBytes, cancel}
	cmd.Stderr = &boundedWriter{io.Discard, 64 << 10, cancel}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	closeErr := output.Close()
	if ctx.Err() != nil {
		return r, fmt.Errorf("Syft stopped: deadline, cancellation or output limit; choose a smaller application directory: %w", ctx.Err())
	}
	if runErr != nil || closeErr != nil {
		return r, errors.New("Syft could not inventory this directory; check read permissions and built artifacts (raw producer errors are private)")
	}
	r, err = inventory.Import(ctx, raw)
	if err != nil {
		return r, err
	}
	r.Scope = "selected-directory; Syft " + Version + "; " + kind + "; no deployment completeness claim"
	// The producer may return package identities from nested artifacts. Filtering
	// here would hide coverage; keep every validated identity and its warnings.
	r.Notices = append(r.Notices, "SYFT_SELECTED_DIRECTORY_IMPORT")
	return r, nil
}
