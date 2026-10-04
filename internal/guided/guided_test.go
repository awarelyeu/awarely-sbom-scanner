package guided

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func npmProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`), 0600)
	// A malformed unrelated ecosystem must not break an npm-only selection.
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte{0xff}, 0600)
	return dir
}
func TestGuidedNPMDefaultIsPrivateLocalOnly(t *testing.T) {
	project := npmProject(t)
	base := t.TempDir()
	var out bytes.Buffer
	code := Run(context.Background(), strings.NewReader("2\n"+project+"\n\nshop\n"+base+"\n\n"), &out, &out, "test")
	if code != 0 {
		t.Fatal(code, out.String())
	}
	files, _ := filepath.Glob(filepath.Join(base, "awarely-results-*", "inventory.cdx.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	b, _ := os.ReadFile(files[0])
	if !bytes.Contains(b, []byte("lodash")) || bytes.Contains(b, []byte(project)) {
		t.Fatal("wrong scope/privacy")
	}
	if strings.Contains(out.String(), "Credential JSON file") {
		t.Fatal("asked for unneeded credentials")
	}
}
func TestGuidedPythonPartialAndRecoveryInstructions(t *testing.T) {
	project := t.TempDir()
	base := t.TempDir()
	os.WriteFile(filepath.Join(project, "requirements.txt"), []byte("requests==2.31.0\n"), 0600)
	var out bytes.Buffer
	code := Run(context.Background(), strings.NewReader("3\n"+project+"\n1\npython-app\n"+base+"\n1\n"), &out, &out, "test")
	if code != 3 || !strings.Contains(out.String(), "synchronization is disabled") || strings.Contains(out.String(), "3. Synchronize") {
		t.Fatal(code, out.String())
	}
	if e := preflight(context.Background(), project, "python", true); e == nil {
		t.Fatal("requirements passed installed environment preflight")
	}
	if e := preflight(context.Background(), project, "java", true); e == nil || !strings.Contains(e.Error(), "JAR/WAR/EAR") {
		t.Fatal(e)
	}
}
func TestGuidedCancelAndInvalidSelection(t *testing.T) {
	for _, input := range []string{"", "q\n", "99\nq\n", "2\n/nonexistent/awarely-test\n"} {
		var out bytes.Buffer
		code := Run(context.Background(), strings.NewReader(input), &out, &out, "test")
		if code == 0 {
			t.Fatal("cancel or invalid input treated as scan success")
		}
	}
}
func TestActionRequiresExplicitConfirmationAndDoesNotLeakToken(t *testing.T) {
	project := npmProject(t)
	r, e := inventory.AppFor(context.Background(), project, "npm")
	if e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"2", "3"} {
		for _, approved := range []string{"no", "yes"} {
			dir := t.TempDir()
			path := filepath.Join(dir, "inventory.json")
			b, _ := inventory.Marshal(r, "sample", "test", time.Now())
			safeio.WriteNew(path, b)
			credentials := api.Credentials{SchemaVersion: 1, APIURL: "https://example.invalid", ApplicationID: "app-test", SourceID: "src-test", Token: "awscan_" + strings.Repeat("a", 32) + "_" + strings.Repeat("B", 43)}
			credPath := filepath.Join(t.TempDir(), "access.json")
			b, _ = json.Marshal(credentials)
			os.WriteFile(credPath, b, 0600)
			var out bytes.Buffer
			calls := 0
			s := session{ctx: context.Background(), reader: bufio.NewScanner(strings.NewReader(action + "\n" + credPath + "\n" + approved + "\n")), out: &out, errOut: &out, version: "test", remote: func(_ context.Context, c api.Credentials, s api.Snapshot, a string) ([]byte, error) {
				calls++
				if c.SourceID != "src-test" || len(s.Components) != 1 {
					t.Fatal("wrong destination/snapshot")
				}
				return []byte(`{"summary":{"matchedCves":1,"componentMatches":1},"coverage":{"unevaluated":[]}}`), nil
			}}
			if code := s.afterExport(path, dir, false); code != 0 {
				t.Fatal(code, out.String())
			}
			want := 0
			if approved == "yes" {
				want = 1
			}
			if calls != want {
				t.Fatal("unapproved request", calls)
			}
			if strings.Contains(out.String(), credentials.Token) {
				t.Fatal("token leaked")
			}
		}
	}
}
func TestPromptCancellationDoesNotWaitForNewline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	done := make(chan int, 1)
	go func() { var out bytes.Buffer; done <- Run(ctx, r, &out, &out, "test") }()
	cancel()
	select {
	case code := <-done:
		if code != 5 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("prompt hung")
	}
}
