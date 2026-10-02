package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const lockFixture = `{"lockfileVersion":3,"packages":{"":{"name":"sample"},"node_modules/@aws-sdk/core":{"version":"3.1.0","resolved":"https://user:SECRET@registry.invalid/core.tgz"},"node_modules/alias":{"name":"actual-package","version":"1.2.3"},"node_modules/parent/node_modules/actual-package":{"version":"1.2.3"},"node_modules/old":{"version":"1.0.0","dev":true}}}`

func TestLockIdentityDedupAndPrivacy(t *testing.T) {
	r := Result{}
	if err := ParseLock(context.Background(), []byte(lockFixture), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 3 {
		t.Fatal(r.Components)
	}
	b, err := Marshal(r, "test app", "test", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"SECRET", "registry.invalid", "node_modules/", "user:"} {
		if strings.Contains(string(b), bad) {
			t.Fatal("private metadata leaked", bad)
		}
	}
	if !strings.Contains(string(b), "pkg:npm/%40aws-sdk/core@3.1.0") {
		t.Fatal(string(b))
	}
}

func TestJSONRejectsAmbiguityAndComplexity(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{} {}`, `{"x":}`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18), "{\"x\":\"" + string([]byte{0xff}) + "\"}", `{"x":"` + strings.Repeat("a", 17000) + `"}`} {
		if err := ValidateJSON(context.Background(), []byte(s)); err == nil {
			t.Fatal("accepted hostile JSON")
		}
	}
}

func TestAppUsesLockWithoutExecutingOrReadingNeighbors(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockFixture), 0600)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"preinstall":"touch /tmp/never-run"}}`), 0600)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("PRIVATE_CANARY"), 0600)
	r, err := App(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inputs) != 1 || len(r.Components) != 3 {
		t.Fatal(r)
	}
	b, _ := Marshal(r, "app", "test", time.Unix(0, 0))
	if strings.Contains(string(b), "PRIVATE_CANARY") {
		t.Fatal("secret read")
	}
}

func TestDeclaredVersionsNeverBecomeInstalled(t *testing.T) {
	r := Result{}
	err := ParsePackageJSON(context.Background(), []byte(`{"dependencies":{"express":"^4.0.0","alias":"npm:real-pkg@1.2.3","local":"file:../SECRET"}}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("missing incomplete coverage")
	}
	for _, c := range r.Components {
		if c.Name == "express" && c.Version != "" {
			t.Fatal("range became exact")
		}
		if c.Properties[0].Value != "declared-manifest" {
			t.Fatal(c)
		}
	}
	b, _ := Marshal(r, "app", "test", time.Unix(0, 0))
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("path leaked")
	}
}

func TestRequirementsDirectivesAndMarkers(t *testing.T) {
	r := Result{}
	err := ParseRequirements(context.Background(), []byte("requests==2.32.0\nzod>=1.0\n-r ../../SECRET\nthing @ https://token@host.invalid/a\nFlask==3.1.0; python_version > '3'\n"), &r)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 3 || len(r.Warnings) < 3 {
		t.Fatal(r)
	}
	for _, c := range r.Components {
		if c.Name == "zod" && c.Version != "" {
			t.Fatal(c)
		}
	}
}

func TestRequirementsDoNotInventPackagesFromURLsOrPaths(t *testing.T) {
	r := Result{}
	err := ParseRequirements(context.Background(), []byte("https://example.invalid/package.whl\nfolder/package\nrequests==1!2.3\nFlask>=2,<4\n"), &r)
	if err != nil || len(r.Components) != 2 {
		t.Fatal(r, err)
	}
	if r.Components[0].Name != "requests" || r.Components[0].Version != "1!2.3" || r.Components[1].Name != "flask" || r.Components[1].Version != "" {
		t.Fatal(r.Components)
	}
}

func TestDedupMergesEvidenceWithoutMarshalMutatingIdentityIndex(t *testing.T) {
	r := Result{}
	for _, name := range []string{"z-last", "JSONStream"} {
		c, err := NewComponent("npm", name, "1.0.0", "resolved-lockfile", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Marshal(r, "app", "test", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	c, _ := NewComponent("npm", "z-last", "1.0.0", "resolved-lockfile", nil)
	c.Properties = append(c.Properties, Property{"awarely:used-in-development", "true"})
	if err := r.Add(c); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(c); err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 2 || r.Components[0].Name != "z-last" || len(r.Components[0].Properties) != 2 || len(r.Components[1].Properties) != 1 {
		t.Fatal(r.Components)
	}
	if r.Components[1].PURL != "pkg:npm/JSONStream@1.0.0" {
		t.Fatal(r.Components[1])
	}
}

func TestLockRejectsMalformedAndWorkspaceIsPartial(t *testing.T) {
	for _, s := range []string{`null`, `{"lockfileVersion":1,"packages":{}}`, `{"lockfileVersion":3,"packages":{"node_modules/x":null}}`, `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"git+https://SECRET"}}}`} {
		r := Result{}
		if ParseLock(context.Background(), []byte(s), &r) == nil {
			t.Fatal("malformed lock accepted")
		}
	}
	r := Result{}
	if err := ParseLock(context.Background(), []byte(`{"lockfileVersion":3,"packages":{"node_modules/local":{"link":true,"resolved":"../../SECRET"}}}`), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("missing workspace warning")
	}
}

func TestHostFocusedClosureKeepsDistroRevision(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0700)
	os.MkdirAll(filepath.Join(dir, "var/lib/dpkg"), 0700)
	os.WriteFile(filepath.Join(dir, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0600)
	status := "Package: nginx\nStatus: install ok installed\nVersion: 1.24.0-2ubuntu7.5\nArchitecture: amd64\nDepends: libssl3 (>= 3), virtual-tls | absent\n\nPackage: libssl3\nStatus: install ok installed\nVersion: 3.0.13-0ubuntu3.6\nArchitecture: amd64\nProvides: virtual-tls\n\nPackage: desktop-tool\nStatus: install ok installed\nVersion: 9.0\nArchitecture: amd64\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: amd64\n"
	os.WriteFile(filepath.Join(dir, "var/lib/dpkg/status"), []byte(status), 0600)
	r, err := Host(context.Background(), dir, "nginx", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 2 || len(r.Warnings) > 0 {
		t.Fatal(r)
	}
	b, _ := Marshal(r, "server", "test", time.Unix(0, 0))
	if !strings.Contains(string(b), "distro=ubuntu-24.04") || !strings.Contains(string(b), "1.24.0-2ubuntu7.5") || strings.Contains(string(b), "desktop-tool") {
		t.Fatal(string(b))
	}
	r, err = Host(context.Background(), dir, "", true)
	if err != nil || len(r.Components) != 3 {
		t.Fatal(r, err)
	}
	r, err = Host(context.Background(), dir, "nginx,not-installed", false)
	if err != nil || len(r.Components) != 2 || len(r.Warnings) != 1 || r.Warnings[0] != "EXPLICIT_SELECTOR_WITHOUT_INSTALLED_MATCH" {
		t.Fatal(r, err)
	}
}

func TestOSMetadataIsDataNotShell(t *testing.T) {
	for _, s := range []string{"ID=ubuntu\nVERSION_ID=$(touch /tmp/pwn)\n", "ID=ubuntu\nID=debian\nVERSION_ID=12", "ID=fedora\nVERSION_ID=42"} {
		if _, _, err := parseOSRelease([]byte(s)); err == nil {
			t.Fatal("invalid OS accepted")
		}
	}
}

func TestComponentLimitAndDeterminism(t *testing.T) {
	r := Result{}
	for i := 0; i < MaxComponents; i++ {
		c := Component{Ref: strings.Repeat("x", i%10) + string(rune(1000+i)), Name: "x", Type: "library"}
		if err := r.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Add(Component{Ref: "extra"}); err == nil {
		t.Fatal("limit not enforced")
	}
	var small Result
	ParseLock(context.Background(), []byte(lockFixture), &small)
	a, _ := Marshal(small, "app", "test", time.Unix(0, 0))
	b, _ := Marshal(small, "app", "test", time.Unix(0, 0))
	if string(a) != string(b) {
		t.Fatal("nondeterministic output")
	}
	var decoded map[string]any
	if err := json.Unmarshal(a, &decoded); err != nil {
		t.Fatal(err)
	}
}

func FuzzJSON(f *testing.F) {
	f.Add([]byte(lockFixture))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxManifestBytes {
			t.Skip()
		}
		ValidateJSON(context.Background(), b)
	})
}
func FuzzLock(f *testing.F) {
	f.Add([]byte(lockFixture))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxManifestBytes {
			t.Skip()
		}
		r := Result{}
		ParseLock(context.Background(), b, &r)
	})
}
func FuzzRequirements(f *testing.F) {
	f.Add([]byte("requests==2.32.0\n-r file\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxManifestBytes {
			t.Skip()
		}
		r := Result{}
		ParseRequirements(context.Background(), b, &r)
	})
}
func FuzzDPKG(f *testing.F) {
	f.Add([]byte("Package: nginx\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxManifestBytes {
			t.Skip()
		}
		parseDPKG(context.Background(), b)
	})
}
