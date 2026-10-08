package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedCommandRejectsInvalidArgumentsBeforePreparation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	app := t.TempDir()
	file := filepath.Join(app, "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{}, {"--ecosystem", "arbitrary"},
		{"--ecosystem", "java", "--path", app, "--output", "-"},
		{"--ecosystem", "java", "--path", app, "--output", "result", "--timeout", "0"},
		{"--ecosystem", "java", "--path", app, "--output", "result", "--timeout", "301"},
		{"--ecosystem", "java", "--path", app, "--output", "result", "--version", "latest"},
		{"--ecosystem", "java", "--path", "/", "--output", "result", "--allow-download"},
		{"--ecosystem", "java", "--path", file, "--output", "result", "--allow-download"},
		{"--ecosystem", "java", "--path", filepath.Join(app, "absent"), "--output", "result", "--allow-download"},
	} {
		var output bytes.Buffer
		if code := runSyft(context.Background(), args, &output); code != 2 {
			t.Fatalf("%v returned %d", args, code)
		}
		if _, err := os.Stat(filepath.Join(home, ".awarely-scan-tools")); !os.IsNotExist(err) {
			t.Fatal("invalid request prepared tool cache")
		}
	}
}

func TestManagedCommandDoesNotPrepareToolForHelp(t *testing.T) {
	var output bytes.Buffer
	if code := runSyft(context.Background(), []string{"--help"}, &output); code != 0 {
		t.Fatal(code)
	}
	if !bytes.Contains(output.Bytes(), []byte("--allow-download")) {
		t.Fatal("missing consent instructions")
	}
}
