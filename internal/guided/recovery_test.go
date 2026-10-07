package guided

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
)

func TestCorrectPathsAndPreflightWithoutExiting(t *testing.T) {
	project, base := npmProject(t), t.TempDir()
	file := filepath.Join(base, "file")
	os.WriteFile(file, []byte("test"), 0600)
	answers := "2\n" + filepath.Join(base, "missing") + "\n" + file + "\n" + base + "\n1\n\"" + project + "\"\n1\n" + strings.Repeat("x", 121) + "\nshop\n" + file + "\n" + base + "\n1\n"
	var out bytes.Buffer
	if code := Run(context.Background(), strings.NewReader(answers), &out, &out, "test"); code != 0 {
		t.Fatal(code, out.String())
	}
	for _, text := range []string{"does not exist", "this is a file", "no npm manifest", "1-120", "Saved local SBOM"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(text, out.String())
		}
	}
	files, _ := filepath.Glob(filepath.Join(base, "awarely-results-*", "inventory.cdx.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
}

func TestBackNavigationAndResultLabelCorrection(t *testing.T) {
	project, base := npmProject(t), t.TempDir()
	answers := "3\nb\n2\n" + project + "\nb\n\n1\nold-label\nb\nnew-label\n" + base + "\n1\n"
	var out bytes.Buffer
	if code := Run(context.Background(), strings.NewReader(answers), &out, &out, "test"); code != 0 {
		t.Fatal(code, out.String())
	}
	files, _ := filepath.Glob(filepath.Join(base, "awarely-results-*", "inventory.cdx.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	data, _ := os.ReadFile(files[0])
	if !bytes.Contains(data, []byte("new-label")) || bytes.Contains(data, []byte("old-label")) {
		t.Fatal("wrong label")
	}
}

func TestPathNormalizationNeverEvaluatesShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, raw := range []string{"~/demo", "\"~/demo\"", "'~/demo'"} {
		p, e := selectedPath(raw)
		if e != nil || p != filepath.Join(home, "demo") {
			t.Fatal(p, e)
		}
	}
	raw := "$(touch should-not-exist)"
	p, e := selectedPath(raw)
	if e != nil || filepath.Base(p) != raw {
		t.Fatal(p, e)
	}
}

func actionFixture(t *testing.T, answers func(string, string) string, remote func(context.Context, api.Credentials, api.Snapshot, string) ([]byte, error)) (*session, string, string, *bytes.Buffer) {
	t.Helper()
	project, dir := npmProject(t), t.TempDir()
	result, e := inventory.AppFor(context.Background(), project, "npm")
	if e != nil {
		t.Fatal(e)
	}
	data, _ := inventory.Marshal(result, "sample", "test", time.Now())
	path := filepath.Join(dir, "inventory.cdx.json")
	os.WriteFile(path, data, 0600)
	c := api.Credentials{SchemaVersion: 1, APIURL: "https://example.invalid", ApplicationID: "app-test", SourceID: "source-test", Token: "awscan_" + strings.Repeat("a", 32) + "_" + strings.Repeat("B", 43)}
	data, _ = json.Marshal(c)
	credential := filepath.Join(t.TempDir(), "access.json")
	os.WriteFile(credential, data, 0600)
	out := &bytes.Buffer{}
	s := &session{ctx: context.Background(), reader: bufio.NewScanner(strings.NewReader(answers(credential, dir))), out: out, errOut: out, version: "test", remote: remote}
	return s, path, dir, out
}

var testReport = []byte(`{"components":[{"ecosystem":"npm","name":"lodash","version":"4.17.15"}],"summary":{"matchedCves":1,"componentMatches":1},"coverage":{"unevaluated":[]},"matches":[{"cveId":"CVE-TEST","severity":"HIGH","components":[{"componentIndex":0,"precision":"version"}]}]}`)

func TestCredentialsCanBeCorrectedAndCheckRetryRequiresConfirmation(t *testing.T) {
	calls := 0
	s, path, dir, out := actionFixture(t, func(c, d string) string { return "2\n/missing/access.json\n" + c + "\nyes\n1\nyes\n" }, func(_ context.Context, _ api.Credentials, _ api.Snapshot, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("temporary failure")
		}
		return testReport, nil
	})
	if code := s.afterExport(path, dir, false); code != 0 || calls != 2 {
		t.Fatal(code, calls, out.String())
	}
	if strings.Count(out.String(), "Send inventory for check") != 2 {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "awscan_") {
		t.Fatal("credential disclosure")
	}
	if data, e := os.ReadFile(filepath.Join(dir, "check-summary.txt")); e != nil || !bytes.Contains(data, []byte("CVE-TEST")) {
		t.Fatal(string(data), e)
	}
}

func TestAmbiguousSyncNeverAutomaticallyRetries(t *testing.T) {
	calls := 0
	s, path, dir, out := actionFixture(t, func(c, d string) string { return "3\n" + c + "\nyes\nyes\n" }, func(_ context.Context, _ api.Credentials, _ api.Snapshot, _ string) ([]byte, error) {
		calls++
		return nil, errors.New("connection lost")
	})
	if code := s.afterExport(path, dir, false); code != 6 || calls != 1 {
		t.Fatal(code, calls, out.String())
	}
	if !strings.Contains(out.String(), "may already have committed") {
		t.Fatal(out.String())
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal(e)
	}
}

func TestSaveReportRecoveryNeverRepeatsCommittedSync(t *testing.T) {
	calls := 0
	base := t.TempDir()
	s, path, dir, out := actionFixture(t, func(c, d string) string {
		os.WriteFile(filepath.Join(d, "sync-result.json"), []byte("keep"), 0600)
		return "3\n" + c + "\nyes\n" + base + "\n"
	}, func(_ context.Context, _ api.Credentials, _ api.Snapshot, _ string) ([]byte, error) {
		calls++
		return []byte(`{"status":"committed"}`), nil
	})
	if code := s.afterExport(path, dir, false); code != 0 || calls != 1 {
		t.Fatal(code, calls, out.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "sync-result.json"))
	if string(data) != "keep" {
		t.Fatal("overwritten report")
	}
	files, _ := filepath.Glob(filepath.Join(base, "awarely-results-*", "sync-result.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
}

func TestResumeValidatesCoverageAndDoesNotScan(t *testing.T) {
	s, path, _, _ := actionFixture(t, func(c, d string) string { return "" }, nil)
	_ = s
	data, _ := os.ReadFile(path)
	data = bytes.ReplaceAll(data, []byte("complete-for-selected-inputs"), []byte("partial"))
	os.WriteFile(path, data, 0600)
	base := t.TempDir()
	var out bytes.Buffer
	code := Run(context.Background(), strings.NewReader("6\n"+path+"\n"+base+"\n3\n1\n"), &out, &out, "test")
	if code != 3 || strings.Contains(out.String(), "3. Synchronize") || strings.Contains(out.String(), "Scanning selected") {
		t.Fatal(code, out.String())
	}
}

func TestSummaryEscapesUntrustedContentAndIncludesAllInFile(t *testing.T) {
	raw := bytes.ReplaceAll(testReport, []byte("CVE-TEST"), []byte(`CVE-TEST\u001b[31m\nINJECTED`))
	text := summaryText(raw, 0)
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\nINJECTED") {
		t.Fatal("terminal injection", text)
	}
	if !strings.Contains(text, "lodash") || !strings.Contains(text, "precision") {
		t.Fatal(text)
	}
}

func TestColorOnlyStylesTrustedHeadings(t *testing.T) {
	var out bytes.Buffer
	code := RunWithColor(context.Background(), strings.NewReader("q\n"), &out, &out, "test", true)
	if code != 5 || !strings.Contains(out.String(), "\x1b[1;36m") {
		t.Fatal(code, out.String())
	}
	out.Reset()
	Run(context.Background(), strings.NewReader("q\n"), &out, &out, "test")
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("redirected output contains color")
	}
}
