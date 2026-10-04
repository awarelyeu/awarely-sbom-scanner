package producer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDownloadRequiresPinnedDigestAndAllowedOrigin(t *testing.T) {
	data := []byte("synthetic verified archive")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	calls := 0
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}
	address := "https://github.com/anchore/syft/releases/download/v" + Version + "/fixture"
	if _, e := download(context.Background(), client, address, digest); e != nil {
		t.Fatal(e)
	}
	if _, e := download(context.Background(), client, address, strings.Repeat("0", 64)); e == nil {
		t.Fatal("tamper accepted")
	}
	for _, address := range []string{"http://github.com/file", "https://github.com.evil.invalid/file", "https://secret@github.com/file", "https://github.com:444/file", "https://localhost/file"} {
		before := calls
		if _, e := download(context.Background(), client, address, digest); e == nil || calls != before {
			t.Fatal("unsafe origin used")
		}
	}
	for _, host := range []string{"https://release-assets.githubusercontent.com/path?sig=example", "https://objects.githubusercontent.com/path"} {
		u, _ := url.Parse(host)
		if !allowedDownload(u) {
			t.Fatal(host)
		}
	}
}
func TestArchiveOnlyExtractsRegularPinnedExecutable(t *testing.T) {
	for _, kind := range []byte{tar.TypeReg, tar.TypeSymlink, tar.TypeLink} {
		var archive bytes.Buffer
		gz := gzip.NewWriter(&archive)
		tw := tar.NewWriter(gz)
		content := []byte("synthetic executable")
		h := &tar.Header{Name: "syft", Mode: 0777, Typeflag: kind, Linkname: "/etc/passwd"}
		if kind == tar.TypeReg {
			h.Size = int64(len(content))
		}
		tw.WriteHeader(h)
		if kind == tar.TypeReg {
			tw.Write(content)
		}
		tw.Close()
		gz.Close()
		target := filepath.Join(t.TempDir(), "syft")
		e := extract(archive.Bytes(), target)
		if kind != tar.TypeReg {
			if e == nil {
				t.Fatal("link extracted")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0700 {
			t.Fatal(info.Mode())
		}
		if e := extract(archive.Bytes(), target); e == nil {
			t.Fatal("overwrote executable")
		}
	}
}
func TestCacheRefusesSymlinkPermissionsAndTamper(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	os.Symlink(dir, cache)
	if _, e := Cached(context.Background(), cache); e == nil {
		t.Fatal("cache symlink accepted")
	}
	os.Remove(cache)
	os.Mkdir(cache, 0755)
	if _, e := Cached(context.Background(), cache); e == nil {
		t.Fatal("public cache accepted")
	}
	os.Chmod(cache, 0700)
	os.WriteFile(filepath.Join(cache, archiveName()), []byte("tampered"), 0600)
	if _, e := Cached(context.Background(), cache); e == nil {
		t.Fatal("tampered archive accepted")
	}
}
func TestProducerOutputBoundCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var b bytes.Buffer
	w := &boundedWriter{&b, 3, cancel}
	if _, e := w.Write([]byte("secret too long")); e == nil || ctx.Err() == nil || b.Len() != 0 {
		t.Fatal("unbounded output")
	}
}
