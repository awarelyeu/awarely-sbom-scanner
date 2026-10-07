package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionsAndChannels(t *testing.T) {
	for _, v := range []string{"dev", "latest", "v01.2.3", "v1.2.3/../../x", "v1.2.3-alpha.01", "v1.2.3\n"} {
		if validVersion(v) {
			t.Fatal(v)
		}
	}
	for _, p := range [][2]string{{"v0.8.0-alpha.2", "v0.8.0-alpha.10"}, {"v1.0.0-rc.1", "v1.0.0"}, {"v1.0.0", "v1.1.0"}, {"v1.0.0-1", "v1.0.0-a"}} {
		if compare(p[0], p[1]) >= 0 || compare(p[1], p[0]) <= 0 {
			t.Fatal(p)
		}
	}
	c := fakeHTTP(func(r *http.Request) (string, int) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("credentials sent")
		}
		return `[{"tag_name":"v1.2.0-alpha.1","prerelease":true},{"tag_name":"v1.1.0"},{"tag_name":"v9.0.0","draft":true},{"tag_name":"../invalid"}]`, 200
	})
	for _, test := range []struct {
		pre  bool
		want string
	}{{false, "v1.1.0"}, {true, "v1.2.0-alpha.1"}} {
		got, e := discover(context.Background(), c, "v1.0.0", "", test.pre)
		if e != nil || got != test.want {
			t.Fatal(got, e)
		}
	}
	c = fakeHTTP(func(r *http.Request) (string, int) { return `{"tag_name":"v1.0.0"}`, 200 })
	if _, e := discover(context.Background(), c, "v1.1.0", "v1.0.0", true); e == nil {
		t.Fatal("downgrade accepted")
	}
}

type tripper func(*http.Request) (*http.Response, error)

func (f tripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fakeHTTP(f func(*http.Request) (string, int)) *http.Client {
	return &http.Client{Transport: tripper(func(r *http.Request) (*http.Response, error) {
		s, code := f(r)
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(s)), Header: http.Header{}}, nil
	})}
}
func TestNetworkPolicy(t *testing.T) {
	for _, raw := range []string{"http://github.com/a", "https://github.com.evil/a", "https://u:p@github.com/a", "https://github.com:443/a", "https://github.com/a#f", "https://127.0.0.1/a"} {
		u, _ := url.Parse(raw)
		if allowedURL(u) {
			t.Fatal(raw)
		}
	}
	for _, code := range []int{404, 429, 503} {
		c := fakeHTTP(func(*http.Request) (string, int) { return "failure", code })
		if _, e := fetch(context.Background(), c, "https://api.github.com/x", 10); e == nil {
			t.Fatal(code)
		}
	}
	c := fakeHTTP(func(*http.Request) (string, int) { return strings.Repeat("x", 20), 200 })
	if _, e := fetch(context.Background(), c, "https://api.github.com/x", 10); e == nil {
		t.Fatal("oversize accepted")
	}
	args := strings.Join(verifyArgs("archive", "proof", "v1.2.3"), " ")
	for _, required := range []string{"--bundle proof", "--repo " + repository, "--signer-workflow " + repository + "/.github/workflows/release.yml", "--source-ref refs/tags/v1.2.3", "--deny-self-hosted-runners"} {
		if !strings.Contains(args, required) {
			t.Fatal(args)
		}
	}
	t.Setenv("GH_TOKEN", "secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("HTTP_PROXY", "secret")
	if strings.Contains(strings.Join(toolEnv("/tmp/private"), " "), "secret") {
		t.Fatal("credential leakage")
	}
}
func archive(t *testing.T, headers []*tar.Header, bodies []string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for i, h := range headers {
		if e := tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Typeflag == tar.TypeReg {
			if _, e := tw.Write([]byte(bodies[i])); e != nil {
				t.Fatal(e)
			}
		}
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}
func TestArchiveBoundaries(t *testing.T) {
	good := &tar.Header{Name: "awarely-scan", Typeflag: tar.TypeReg, Size: 3}
	for _, h := range []*tar.Header{{Name: "../escape", Typeflag: tar.TypeReg, Size: 3}, {Name: "/absolute", Typeflag: tar.TypeReg, Size: 3}, {Name: "awarely-scan", Typeflag: tar.TypeSymlink, Linkname: "outside"}} {
		b := archive(t, []*tar.Header{h}, []string{"bin"})
		if _, e := unpack(b, map[string]int64{"awarely-scan": 10}, 10000); e == nil {
			t.Fatal(h)
		}
	}
	b := archive(t, []*tar.Header{good, good}, []string{"bin", "bin"})
	if _, e := unpack(b, map[string]int64{"awarely-scan": 10}, 10000); e == nil {
		t.Fatal("duplicate accepted")
	}
	b = archive(t, []*tar.Header{good}, []string{"bin"})
	for _, limit := range []int64{1, 10} {
		if _, e := unpack(b, map[string]int64{"awarely-scan": 10}, limit); e == nil {
			t.Fatal("expansion accepted")
		}
	}
	if _, e := unpack(b, map[string]int64{"awarely-scan": 2}, 10000); e == nil {
		t.Fatal("member too large")
	}
	if _, e := unpack(b[:len(b)-5], map[string]int64{"awarely-scan": 10}, 10000); e == nil {
		t.Fatal("truncation accepted")
	}
	if got, e := unpack(b, map[string]int64{"awarely-scan": 10}, 10000); e != nil || string(got["awarely-scan"]) != "bin" {
		t.Fatal(e)
	}
}
func fixture(t *testing.T) (string, *installation) {
	t.Helper()
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	dir, e := os.MkdirTemp(home, ".awarely-update-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	exe := filepath.Join(dir, "awarely-scan")
	os.WriteFile(exe, binary("v1.0.0"), 0700)
	i, e := openInstallation(exe)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(i.close)
	return exe, i
}
func binary(v string) []byte { return []byte("#!/bin/sh\nprintf 'awarely-scan " + v + "\\n'\n") }
func TestAtomicUpdateRollbackAndTampering(t *testing.T) {
	exe, i := fixture(t)
	old, next := binary("v1.0.0"), binary("v1.1.0")
	if e := i.replace(context.Background(), old, next, "v1.0.0", "v9.0.0", true); e == nil {
		t.Fatal("wrong candidate accepted")
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, old) {
		t.Fatal("old binary changed after failed probe")
	}
	if e := i.replace(context.Background(), old, next, "v1.0.0", "v1.1.0", true); e != nil {
		t.Fatal(e)
	}
	b, e := i.previous(next)
	if e != nil || b.Version != "v1.0.0" {
		t.Fatal(e)
	}
	if e = i.replace(context.Background(), next, b.Binary, "v1.1.0", b.Version, false); e != nil {
		t.Fatal(e)
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, old) {
		t.Fatal("rollback did not restore exact bytes")
	}
	// Corruption of a backup must stop restoration before any execution.
	record := filepath.Join(i.state, digest(next)+".json")
	data, _ := os.ReadFile(record)
	var bad backup
	json.Unmarshal(data, &bad)
	bad.Binary = []byte("tampered")
	data, _ = json.Marshal(bad)
	os.WriteFile(record, data, 0600)
	if _, e = i.previous(next); e == nil {
		t.Fatal("tampered backup accepted")
	}
}
func TestInstallConcurrencyAndFiles(t *testing.T) {
	exe, i := fixture(t)
	if other, e := openInstallation(exe); e == nil {
		other.close()
		t.Fatal("concurrent update lock acquired")
	}
	old := binary("v1.0.0")
	os.WriteFile(exe, binary("v1.0.1"), 0700)
	if e := i.replace(context.Background(), old, binary("v1.1.0"), "v1.0.0", "v1.1.0", true); e == nil {
		t.Fatal("changed installation accepted")
	}
	os.Remove(exe)
	os.Symlink(filepath.Join(i.dir, "elsewhere"), exe)
	if _, e := i.read(i.name, maxBinary); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(exe)
	os.WriteFile(exe, old, 0777)
	os.Chmod(exe, 0777)
	if _, e := i.read(i.name, maxBinary); e == nil {
		t.Fatal("writable binary accepted")
	}
	os.Chmod(exe, 0700)
	os.Link(exe, filepath.Join(i.dir, "hardlink"))
	if _, e := i.read(i.name, maxBinary); e == nil {
		t.Fatal("hardlink accepted")
	}
}
func TestVerifierTamperingNeverExecutes(t *testing.T) {
	c := fakeHTTP(func(*http.Request) (string, int) { return "malicious verifier", 200 })
	if _, e := verifiedBinary(context.Background(), c, t.TempDir(), "v1.0.0"); e == nil || !strings.Contains(e.Error(), "checksum mismatch") {
		t.Fatal(e)
	}
}
func TestConsentIsExplicit(t *testing.T) {
	for _, answer := range []string{"", "\n", "y\n", "YES\n", "no\n", strings.Repeat("x", 4096)} {
		if approved(strings.NewReader(answer), io.Discard, false) {
			t.Fatal("implicit consent")
		}
	}
	if !approved(strings.NewReader("yes\n"), io.Discard, false) {
		t.Fatal("yes rejected")
	}
}

func TestFailedProvenanceNeverExecutesCandidate(t *testing.T) {
	prefix := "gh_" + verifierVersion + "_linux_" + runtime.GOARCH
	script := "#!/bin/sh\n[ -z \"${GH_TOKEN:-}${AWS_SECRET_ACCESS_KEY:-}\" ] || exit 77\nexit 1\n"
	verifier := archive(t, []*tar.Header{{Name: prefix + "/bin/gh", Typeflag: tar.TypeReg, Size: int64(len(script))}, {Name: prefix + "/LICENSE", Typeflag: tar.TypeReg, Size: 3}}, []string{script, "MIT"})
	saved := verifierPins[runtime.GOARCH]
	verifierPins[runtime.GOARCH] = digest(verifier)
	t.Cleanup(func() { verifierPins[runtime.GOARCH] = saved })
	c := fakeHTTP(func(r *http.Request) (string, int) {
		if strings.Contains(r.URL.Path, "/cli/cli/") {
			return string(verifier), 200
		}
		if strings.HasSuffix(r.URL.Path, ".jsonl") {
			return "untrusted proof", 200
		}
		return "not an archive; verification must fail first", 200
	})
	t.Setenv("GH_TOKEN", "must-not-be-used")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-be-used")
	if _, e := verifiedBinary(context.Background(), c, t.TempDir(), "v1.0.0"); e == nil || !strings.Contains(e.Error(), "provenance verification failed") {
		t.Fatal(e)
	}
}
