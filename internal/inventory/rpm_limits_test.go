package inventory

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func amplificationHeader(count int, memory bool) []byte {
	type field struct {
		tag, typ, count uint32
		data            []byte
	}
	text := func(tag uint32, s string) field { return field{tag, 6, 1, append([]byte(s), 0)} }
	fields := []field{text(1000, "nginx"), text(1001, "1.0"), text(1002, "1.el9"), text(1011, "Rocky Enterprise Software Foundation"), text(1022, "x86_64")}
	if memory {
		fields = append(fields, field{1118, 8, 1, append([]byte(strings.Repeat("d", 4096)), 0)}, field{1117, 8, uint32(count), []byte(strings.Repeat("a\x00", count))}, field{1116, 4, uint32(count), make([]byte, 4*count)})
	} else {
		fields = append(fields, field{1047, 8, uint32(count), []byte(strings.Repeat("a\x00", count))}, field{1049, 8, uint32(count), []byte(strings.Repeat("a\x00", count))})
	}
	b := make([]byte, 8+16*len(fields))
	binary.BigEndian.PutUint32(b[:4], uint32(len(fields)))
	var data []byte
	for i, f := range fields {
		e := b[8+i*16 : 24+i*16]
		binary.BigEndian.PutUint32(e[:4], f.tag)
		binary.BigEndian.PutUint32(e[4:8], f.typ)
		binary.BigEndian.PutUint32(e[8:12], uint32(len(data)))
		binary.BigEndian.PutUint32(e[12:], f.count)
		data = append(data, f.data...)
	}
	binary.BigEndian.PutUint32(b[4:8], uint32(len(data)))
	return append(b, data...)
}
func TestRPMExpandedMetadataLimit(t *testing.T) {
	if _, err := parseRPMHeader(amplificationHeader(8192, true)); err == nil {
		t.Fatal("expanded file metadata must fail before unbounded allocation")
	}
}
func TestRPMDuplicateCapabilitiesRemainLinear(t *testing.T) {
	header := amplificationHeader(12000, false)
	p, err := parseRPMHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Requires) != 1 || len(p.Provides) != 1 {
		t.Fatal("duplicate capabilities retained")
	}
	if cap(p.Requires) > 8 || cap(p.Provides) > 8 {
		t.Fatal("duplicate backing arrays retained")
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0700)
	os.MkdirAll(filepath.Join(root, "var/lib/rpm"), 0700)
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=rocky\nVERSION_ID=9\n"), 0600)
	os.WriteFile(filepath.Join(root, "var/lib/rpm/Packages"), bdbFixture(header), 0600)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := Host(ctx, root, "nginx", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Components) != 1 {
		t.Fatal("unexpected selected inventory")
	}
}
func TestRPMRichExpressionSetOperationsAreBudgeted(t *testing.T) {
	ids := []string{"one", "two", "three", "four"}
	steps := 0
	result := rpmDependencyWithBudget("(a and b and c and d)", func(string) []string { return ids }, func() bool { steps++; return steps <= 30 })
	if result.covered {
		t.Fatal("rich expression ignored cumulative set-operation budget")
	}
	if steps <= 30 {
		t.Fatal("test did not reach aggregate work limit")
	}
}
