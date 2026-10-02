package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRPMReferenceDatabases(t *testing.T) {
	dir := os.Getenv("AWARELY_RPM_TESTDATA")
	if dir == "" {
		t.Skip("optional independently generated RPM databases")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "*"))
	for _, path := range paths {
		if filepath.Base(filepath.Dir(path)) == "centos5-plain" {
			continue
		}
		if filepath.Base(path) != "Packages" && filepath.Base(path) != "rpmdb.sqlite" {
			continue
		}
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			count := 0
			e = rpmRecords(context.Background(), b, func(raw []byte) error { _, err := parseRPMHeader(raw); count++; return err })
			if e != nil {
				t.Fatalf("after %d headers: %v", count, e)
			}
			t.Logf("read %d packages", count)
		})
	}
}
func FuzzRPMDatabase(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("SQLite format 3\x00"))
	f.Add(bdbFixture(rpmTestHeader()))
	db, wal := sqliteFixture(f)
	snapshot, err := sqliteWAL(context.Background(), db, wal)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(snapshot)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_ = rpmRecords(context.Background(), b, func(raw []byte) error { _, e := parseRPMHeader(raw); return e })
	})
}
func FuzzRPMHeader(f *testing.F) {
	f.Add(rpmTestHeader())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseRPMHeader(b) })
}
