// Package update is the explicit, consented release-update boundary.
// Collectors never call it. Release discovery is a hint, not a trust decision.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repository = "awarelyeu/awarely-sbom-scanner"
const maxBinary = 32 << 20
const verifierVersion = "2.102.0"

var verifierPins = map[string]string{
	"amd64": "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386",
	"arm64": "7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484",
}
var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(?:-([a-z0-9]+(?:\.[a-z0-9]+)*))?$`)

func validVersion(v string) bool {
	if len(v) > 80 || !versionPattern.MatchString(v) {
		return false
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		for _, part := range strings.Split(v[i+1:], ".") {
			if len(part) > 18 {
				return false
			}
			if _, e := strconv.Atoi(part); e == nil && len(part) > 1 && part[0] == '0' {
				return false
			}
		}
	}
	return true
}
func compare(a, b string) int {
	aa, bb := versionPattern.FindStringSubmatch(a), versionPattern.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(aa[i])
		y, _ := strconv.Atoi(bb[i])
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	if aa[4] == bb[4] {
		return 0
	}
	if aa[4] == "" {
		return 1
	}
	if bb[4] == "" {
		return -1
	}
	ap, bp := strings.Split(aa[4], "."), strings.Split(bb[4], ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		if ap[i] == bp[i] {
			continue
		}
		x, xe := strconv.ParseUint(ap[i], 10, 64)
		y, ye := strconv.ParseUint(bp[i], 10, 64)
		if xe == nil && ye == nil {
			if x < y {
				return -1
			}
			return 1
		}
		if xe == nil {
			return -1
		}
		if ye == nil {
			return 1
		}
		return strings.Compare(ap[i], bp[i])
	}
	if len(ap) < len(bp) {
		return -1
	}
	return 1
}
func allowedURL(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" {
		return false
	}
	switch u.Host {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}
func client() *http.Client {
	return &http.Client{Timeout: 180 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 4 || !allowedURL(r.URL) {
			return errors.New("release redirect rejected")
		}
		return nil
	}}
}
func fetch(ctx context.Context, c *http.Client, address string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil || !allowedURL(req.URL) {
		return nil, errors.New("release URL rejected")
	}
	req.Header.Set("User-Agent", "Awarely-Scan-Updater")
	req.Header.Set("Accept", "application/vnd.github+json")
	r, e := c.Do(req)
	if e != nil {
		return nil, errors.New("download failed; check HTTPS access and retry")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("release download returned HTTP %d; nothing installed", r.StatusCode)
	}
	if r.ContentLength > limit {
		return nil, errors.New("release response exceeds size limit")
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("release download is incomplete or too large")
	}
	return b, nil
}

type release struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

func discover(ctx context.Context, c *http.Client, current, target string, pre bool) (string, error) {
	endpoint := "https://api.github.com/repos/" + repository + "/releases?per_page=100"
	if target != "" {
		if !validVersion(target) {
			return "", errors.New("use an exact release tag such as v0.9.0-alpha.1")
		}
		endpoint = "https://api.github.com/repos/" + repository + "/releases/tags/" + target
	}
	b, e := fetch(ctx, c, endpoint, 2<<20)
	if e != nil {
		return "", e
	}
	var releases []release
	if target != "" {
		var r release
		e = json.Unmarshal(b, &r)
		releases = []release{r}
	} else {
		e = json.Unmarshal(b, &releases)
	}
	if e != nil {
		return "", errors.New("invalid release metadata")
	}
	best := ""
	for _, r := range releases {
		if r.Draft || !validVersion(r.Tag) {
			continue
		}
		if target != "" && r.Tag != target {
			continue
		}
		if target == "" && !pre && (r.Prerelease || strings.Contains(r.Tag, "-")) {
			continue
		}
		if best == "" || compare(r.Tag, best) > 0 {
			best = r.Tag
		}
	}
	if best == "" {
		return "", errors.New("no eligible published release found")
	}
	if compare(best, current) < 0 {
		if target == "" {
			return current, nil
		}
		return "", errors.New("downgrade refused; use explicit rollback for the saved previous binary")
	}
	return best, nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Extract only the named regular entries into memory, never archive paths.
func unpack(b []byte, wanted map[string]int64, total int64) (map[string][]byte, error) {
	gz, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return nil, errors.New("invalid release archive")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: total + 1}
	tr := tar.NewReader(limited)
	found := map[string][]byte{}
	seen := map[string]bool{}
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || count > 4096 {
			return nil, errors.New("invalid or oversized release archive")
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") || seen[name] {
			return nil, errors.New("unsafe or duplicate archive entry")
		}
		seen[name] = true
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return nil, errors.New("archive links and special files are rejected")
		}
		if limit, ok := wanted[name]; ok {
			if h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > limit {
				return nil, errors.New("invalid release member")
			}
			data, e := io.ReadAll(io.LimitReader(tr, limit+1))
			if e != nil || int64(len(data)) != h.Size {
				return nil, errors.New("truncated release member")
			}
			found[name] = data
		}
	}
	// Drain the bounded gzip stream to validate its checksum and expansion limit.
	if _, e = io.Copy(io.Discard, limited); e != nil || limited.N <= 0 {
		return nil, errors.New("archive integrity or expansion limit failed")
	}
	for name := range wanted {
		if _, ok := found[name]; !ok {
			return nil, errors.New("required archive member missing")
		}
	}
	return found, nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.Len() {
		return 0, errors.New("tool output limit exceeded")
	}
	return w.Buffer.Write(p)
}
func toolEnv(dir string) []string {
	return []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "GH_CONFIG_DIR=" + filepath.Join(dir, "gh-config"), "GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1", "LANG=C", "LC_ALL=C", "NO_COLOR=1"}
}
func verifyArgs(archive, bundle, tag string) []string {
	return []string{"attestation", "verify", archive, "--bundle", bundle, "--repo", repository, "--signer-workflow", repository + "/.github/workflows/release.yml", "--source-ref", "refs/tags/" + tag, "--deny-self-hosted-runners"}
}
func verifiedBinary(ctx context.Context, c *http.Client, dir, tag string) ([]byte, error) {
	arch := runtime.GOARCH
	pin := verifierPins[arch]
	if pin == "" {
		return nil, errors.New("unsupported update architecture")
	}
	prefix := "gh_" + verifierVersion + "_linux_" + arch
	data, e := fetch(ctx, c, "https://github.com/cli/cli/releases/download/v"+verifierVersion+"/"+prefix+".tar.gz", 40<<20)
	if e != nil {
		return nil, e
	}
	if digest(data) != pin {
		return nil, errors.New("verifier checksum mismatch; nothing executed")
	}
	parts, e := unpack(data, map[string]int64{prefix + "/bin/gh": 200 << 20, prefix + "/LICENSE": 128 << 10}, 220<<20)
	if e != nil {
		return nil, e
	}
	gh := filepath.Join(dir, "gh")
	if e = os.WriteFile(gh, parts[prefix+"/bin/gh"], 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(filepath.Join(dir, "GH-LICENSE"), parts[prefix+"/LICENSE"], 0600); e != nil {
		return nil, e
	}
	name := "awarely-scan_" + tag + "_linux_" + arch + ".tar.gz"
	base := "https://github.com/" + repository + "/releases/download/" + tag + "/"
	data, e = fetch(ctx, c, base+name, 40<<20)
	if e != nil {
		return nil, e
	}
	bundle, e := fetch(ctx, c, base+name+".sigstore.jsonl", 4<<20)
	if e != nil {
		return nil, e
	}
	archivePath, bundlePath := filepath.Join(dir, name), filepath.Join(dir, "proof.jsonl")
	if e = os.WriteFile(archivePath, data, 0600); e != nil {
		return nil, e
	}
	if e = os.WriteFile(bundlePath, bundle, 0600); e != nil {
		return nil, e
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(verifyCtx, gh, verifyArgs(archivePath, bundlePath, tag)...)
	cmd.Env = toolEnv(dir)
	cmd.Dir = dir
	output := &boundedOutput{limit: 128 << 10}
	cmd.Stdout = output
	cmd.Stderr = output
	if e = cmd.Run(); e != nil {
		return nil, errors.New("release provenance verification failed; installed binary unchanged")
	}
	parts, e = unpack(data, map[string]int64{"awarely-scan": maxBinary, "SHA256SUMS": 4096}, 48<<20)
	if e != nil {
		return nil, e
	}
	fields := strings.Fields(string(parts["SHA256SUMS"]))
	if len(fields) != 2 || fields[1] != "awarely-scan" || fields[0] != digest(parts["awarely-scan"]) {
		return nil, errors.New("binary checksum mismatch")
	}
	return parts["awarely-scan"], nil
}
func binaryVersion(ctx context.Context, name, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, "version")
	cmd.Env = toolEnv(dir)
	cmd.Dir = dir
	output := &boundedOutput{limit: 4096}
	cmd.Stdout = output
	cmd.Stderr = output
	if e := cmd.Run(); e != nil {
		return "", errors.New("binary version check failed")
	}
	text := strings.TrimSpace(output.String())
	v := strings.TrimPrefix(text, "awarely-scan ")
	if text == v || !validVersion(v) {
		return "", errors.New("binary returned an invalid version")
	}
	return v, nil
}
