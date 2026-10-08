package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeEcosystemSelectionInMixedProject(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}`,
		"requirements.txt":  "requests==2.31.0\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		ecosystem   string
		count, code int
	}{{"npm", 1, 0}, {"python", 1, 3}, {"", 2, 3}, {"java", 0, 2}} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "inventory.json")
			args := []string{"app", "--path", dir, "--output", output}
			if tc.ecosystem != "" {
				args = append(args, "--ecosystem", tc.ecosystem)
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr); code != tc.code {
				t.Fatalf("code=%d: %s", code, stderr.String())
			}
			if tc.code == 2 {
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("invalid ecosystem published output")
				}
				return
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var sbom struct {
				Components []struct {
					Name string `json:"name"`
				} `json:"components"`
			}
			if err := json.Unmarshal(data, &sbom); err != nil {
				t.Fatal(err)
			}
			if len(sbom.Components) != tc.count {
				t.Fatalf("components=%v", sbom.Components)
			}
			if tc.ecosystem == "npm" && sbom.Components[0].Name != "demo" {
				t.Fatal("npm included Python dependency")
			}
			if tc.ecosystem == "python" && sbom.Components[0].Name != "requests" {
				t.Fatal("Python included npm dependency")
			}
		})
	}
}

func TestCLIContracts(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}`), 0600)
	dest := filepath.Join(t.TempDir(), "report.json")
	cases := []struct {
		args []string
		code int
	}{
		{nil, 0}, {[]string{"version"}, 0}, {[]string{"check"}, 2}, {[]string{"sync"}, 2},
		{[]string{"app"}, 2}, {[]string{"app", "--timeout", "0", "--output", dest}, 2},
		{[]string{"host", "--all-packages", "--select", "nginx", "--output", dest}, 2},
		{[]string{"app", "--path", dir, "--output", dest, "--name", "sample"}, 0},
		{[]string{"app", "--path", dir, "--output", dest}, 4},
	}
	for _, c := range cases {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), c.args, &out, &stderr); code != c.code {
			t.Fatalf("%v: got %d expected %d: %s", c.args, code, c.code, stderr.String())
		}
	}
}
func TestPartialAndErrorsAreNotSuccess(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests>=2\n"), 0600)
	var out, stderr bytes.Buffer
	code := run(context.Background(), []string{"app", "--path", dir, "--output", filepath.Join(t.TempDir(), "report.json")}, &out, &stderr)
	if code != 3 || !strings.Contains(stderr.String(), "Partial inventory") {
		t.Fatal(code, stderr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code = run(ctx, []string{"app", "--path", dir, "--output", filepath.Join(t.TempDir(), "report.json")}, &out, &stderr); code != 5 {
		t.Fatal(code)
	}
}
