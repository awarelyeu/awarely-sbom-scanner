package inventory

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func rpmTestHeader() []byte {
	fields := []struct {
		tag   uint32
		value string
	}{{1000, "openssl-libs"}, {1001, "3.0.7"}, {1002, "27.el9"}, {1011, "Rocky Enterprise Software Foundation"}, {1022, "x86_64"}, {1044, "openssl-3.0.7-27.el9.src.rpm"}, {1047, "libcrypto.so.3()(64bit)"}, {1049, "rpmlib(PayloadIsXz)"}}
	b := make([]byte, 8+16*len(fields))
	binary.BigEndian.PutUint32(b[:4], uint32(len(fields)))
	var data []byte
	for i, f := range fields {
		p := b[8+i*16 : 24+i*16]
		binary.BigEndian.PutUint32(p[:4], f.tag)
		typ := uint32(6)
		if f.tag == 1047 || f.tag == 1049 {
			typ = 8
		}
		binary.BigEndian.PutUint32(p[4:8], typ)
		binary.BigEndian.PutUint32(p[8:12], uint32(len(data)))
		binary.BigEndian.PutUint32(p[12:], 1)
		data = append(data, []byte(f.value)...)
		data = append(data, 0)
	}
	binary.BigEndian.PutUint32(b[4:8], uint32(len(data)))
	return append(b, data...)
}
func sqliteFixture(t testing.TB) ([]byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Python's independent SQLite writer creates the actual on-disk and WAL format.
	code := `import sqlite3,sys,pathlib
p=pathlib.Path(sys.argv[1]);c=sqlite3.connect(str(p/'live'))
c.execute('PRAGMA page_size=512');c.execute('PRAGMA journal_mode=WAL')
c.execute('CREATE TABLE Packages(hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)');c.commit()
c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
c.execute('INSERT INTO Packages(blob) VALUES (?)',(bytes.fromhex(sys.argv[2]),));c.commit()
(p/'snapshot').write_bytes((p/'live').read_bytes());(p/'snapshot-wal').write_bytes((p/'live-wal').read_bytes())
c.close()
`
	if out, e := exec.CommandContext(ctx, "python3", "-c", code, dir, hex.EncodeToString(rpmTestHeader())).CombinedOutput(); e != nil {
		t.Fatalf("SQLite oracle: %v %s", e, out)
	}
	db, e := os.ReadFile(filepath.Join(dir, "snapshot"))
	if e != nil {
		t.Fatal(e)
	}
	wal, e := os.ReadFile(filepath.Join(dir, "snapshot-wal"))
	if e != nil {
		t.Fatal(e)
	}
	return db, wal
}
func TestSQLiteCommittedWALAndRPMHeader(t *testing.T) {
	db, wal := sqliteFixture(t)
	snapshot, e := sqliteWAL(context.Background(), db, wal)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	e = rpmRecords(context.Background(), snapshot, func(b []byte) error {
		p, e := parseRPMHeader(b)
		if e != nil {
			return e
		}
		if p.Name != "openssl-libs" || p.Version != "0:3.0.7-27.el9" || p.SourceName != "openssl" {
			t.Fatalf("wrong metadata: %+v", p)
		}
		count++
		return nil
	})
	if e != nil || count != 1 {
		t.Fatalf("records=%d, error=%v", count, e)
	}
	for _, mutate := range []func([]byte){func(b []byte) { b[0] ^= 1 }, func(b []byte) { b[len(b)-1] ^= 1 }, func(b []byte) { b[40] ^= 1 }} {
		copy := bytes.Clone(wal)
		mutate(copy)
		if _, e := sqliteWAL(context.Background(), db, copy); e == nil {
			t.Fatal("corrupt WAL accepted")
		}
	}
	if _, e := sqliteWAL(context.Background(), db, wal[:len(wal)-1]); e == nil {
		t.Fatal("partial WAL accepted")
	}
	// A self-reference must not turn table traversal into an unbounded recursion.
	corrupt := bytes.Clone(snapshot)
	size := int(binary.BigEndian.Uint16(corrupt[16:18]))
	corrupt[size] = 5
	binary.BigEndian.PutUint16(corrupt[size+3:size+5], 0)
	binary.BigEndian.PutUint32(corrupt[size+8:size+12], 2)
	if e := rpmRecords(context.Background(), corrupt, func([]byte) error { return nil }); e == nil {
		t.Fatal("cyclic B-tree accepted")
	}
}
func bdbFixture(header []byte) []byte {
	const size = 512
	pages := (len(header) + size - 27) / (size - 26)
	b := make([]byte, (2+pages)*size)
	le := binary.LittleEndian
	le.PutUint32(b[12:16], 0x61561)
	le.PutUint32(b[16:20], 9)
	le.PutUint32(b[20:24], size)
	b[25] = 8
	le.PutUint32(b[32:36], uint32(1+pages))
	p := b[size : 2*size]
	le.PutUint32(p[8:12], 1)
	p[25] = 13
	le.PutUint16(p[20:22], 2)
	le.PutUint16(p[26:28], 507)
	le.PutUint16(p[28:30], 495)
	p[507] = 1
	le.PutUint32(p[508:512], 1)
	p[495] = 3
	le.PutUint32(p[499:503], 2)
	le.PutUint32(p[503:507], uint32(len(header)))
	for i := 0; i < pages; i++ {
		p = b[(i+2)*size : (i+3)*size]
		p[25] = 7
		le.PutUint32(p[8:12], uint32(i+2))
		take := min(len(header), size-26)
		if i+1 < pages {
			le.PutUint32(p[16:20], uint32(i+3))
		}
		le.PutUint16(p[22:24], uint16(take))
		copy(p[26:], header[:take])
		header = header[take:]
	}
	return b
}
func TestBDBOverflowBoundsAndCycles(t *testing.T) {
	want := rpmTestHeader()
	b := bdbFixture(want)
	count := 0
	if e := bdbRecords(context.Background(), b, func(got []byte) error {
		count++
		if !bytes.Equal(got, want) {
			t.Fatal("wrong BDB header")
		}
		return nil
	}); e != nil || count != 1 {
		t.Fatalf("%d %v", count, e)
	}
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[1040:1044], 2) }, func(b []byte) { binary.LittleEndian.PutUint16(b[540:542], 65535) }, func(b []byte) { binary.LittleEndian.PutUint32(b[1015:1019], 0xffffffff) }} {
		copy := bytes.Clone(b)
		mutate(copy)
		if e := bdbRecords(context.Background(), copy, func([]byte) error { return nil }); e == nil {
			t.Fatal("malformed BDB accepted")
		}
	}
}
func TestHostRPMAutoDetectionSnapshotAndSpecialFiles(t *testing.T) {
	for _, distro := range []string{"rocky", "almalinux", "amzn"} {
		t.Run(distro, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range []string{"etc", "var/lib/rpm"} {
				if e := os.MkdirAll(filepath.Join(root, d), 0700); e != nil {
					t.Fatal(e)
				}
			}
			os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID="+distro+"\nVERSION_ID=9.6\n"), 0600)
			db, wal := sqliteFixture(t)
			os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), db, 0600)
			os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite-wal"), wal, 0600)
			r, e := Host(context.Background(), root, "openssl-libs", false)
			if e != nil || len(r.Components) != 1 || len(r.Warnings) != 0 {
				t.Fatalf("%+v %v", r, e)
			}
			if !bytes.Contains([]byte(r.Components[0].PURL), []byte("pkg:rpm/"+distro+"/")) {
				t.Fatal("distribution lost")
			}
			os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite-journal"), []byte("busy"), 0600)
			if _, e := Host(context.Background(), root, "openssl-libs", false); e == nil {
				t.Fatal("active journal accepted")
			}
		})
	}
}
func FuzzRPMWAL(f *testing.F) {
	db, wal := sqliteFixture(f)
	f.Add(db, wal)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, db, wal []byte) {
		if len(db)+len(wal) > 1<<20 {
			return
		}
		_, _ = sqliteWAL(context.Background(), db, wal)
	})
}
