package inventory

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestRPMRichDependencyCoverage(t *testing.T) {
	provider := func(name string) []string {
		return map[string][]string{"a": {"a"}, "b": {"b"}, "capA": {"a"}, "libc.so.6()(64bit)": {"libc"}}[name]
	}
	tests := []struct {
		expression string
		covered    bool
	}{
		{"(missing if absent)", true}, {"(missing if a)", false}, {"(a or missing)", true}, {"(a and missing)", false},
		{"(a if b else missing)", true}, {"(a if absent else missing)", false},
		{"(a unless b)", true}, {"(missing unless absent)", false}, {"(a unless b else missing)", false},
		{"(a with capA)", true}, {"(a with b)", false}, {"(a without capA)", false}, {"(a without b)", true},
		{"(libc.so.6()(64bit) and (a or missing))", true},
		// A versioned condition might not be satisfied. Neither branch can be
		// silently dropped merely because its package name exists in the database.
		{"(a if b >= 2 else missing)", false}, {"(missing unless b >= 2)", false},
		{"(missing if absent >= 2)", true}, {"(a or b or missing)", true},
		{"(a and b and missing)", false}, {"(a xor b)", false}, {"(a and)", false}, {"(a if b else)", false},
	}
	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			r := rpmDependency(tt.expression, provider)
			if r.covered != tt.covered {
				t.Fatalf("covered=%v want %v", r.covered, tt.covered)
			}
		})
	}
	r := rpmDependency("(a if b else libc.so.6()(64bit))", provider)
	if len(r.ids) != 3 {
		t.Fatal("installed branch/condition providers omitted", r.ids)
	}
	if rpmDependency(strings.Repeat("(", 40)+"a"+strings.Repeat(" and a)", 40), provider).covered {
		t.Fatal("depth bound ignored")
	}
}
func TestRPMRepeatedSourceIdentity(t *testing.T) {
	b := rpmTestHeader()
	n := int(binary.BigEndian.Uint32(b[:4]))
	entry := bytes.Clone(b[8+5*16 : 24+5*16])
	// The installed header may repeat its source tag outside the original region.
	repeated := append(bytes.Clone(b[:8+n*16]), entry...)
	repeated = append(repeated, b[8+n*16:]...)
	binary.BigEndian.PutUint32(repeated[:4], uint32(n+1))
	if _, err := parseRPMHeader(repeated); err != nil {
		t.Fatal(err)
	}
	// The same tag pointing at another identity must still fail closed.
	binary.BigEndian.PutUint32(repeated[8+n*16+8:8+n*16+12], 0)
	if _, err := parseRPMHeader(repeated); err == nil {
		t.Fatal("conflicting source identity accepted")
	}
}
func FuzzRPMDependency(f *testing.F) {
	for _, seed := range []string{"(a if b else c)", "(a and (b or c))", "libc.so.6()(64bit)", "(a >= 1 with b)"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rpmDependency(s, func(name string) []string {
			if name == "a" {
				return []string{"a"}
			}
			return nil
		})
	})
}
