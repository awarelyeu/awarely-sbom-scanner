package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
