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

func importFixture(t *testing.T, input string) (Result, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(p, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	return Import(context.Background(), p)
}
func TestImportedSBOMIdentitiesAndPrivacy(t *testing.T) {
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"private":"SECRET"},"components":[{"type":"library","group":"org.example","name":"core","version":"1.2.0.Final","purl":"pkg:maven/org.example/core@1.2.0.Final?type=jar","externalReferences":[{"url":"https://token:SECRET@example.invalid"}],"properties":[{"name":"syft:location:0:path","value":"/private/SECRET"}]},{"name":"core","group":"org.example","version":"1.2.0.Final","purl":"pkg:maven/org.example/core@1.2.0.Final"}]}`
	r, err := importFixture(t, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 1 || len(r.Warnings) != 0 {
		t.Fatal(r)
	}
	b, err := Marshal(r, "demo", "test", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") || !strings.Contains(string(b), "imported-sbom") {
		t.Fatal(string(b))
	}
}
func TestImportedApplicationEcosystems(t *testing.T) {
	for _, c := range []struct{ eco, group, name, version string }{{"npm", "@demo", "core", "1.2.3"}, {"pypi", "", "Demo_Pkg", "1.2.3"}, {"maven", "org.example", "core", "1.0-rc1"}, {"nuget", "", "Example.Core", "1.2.3"}, {"golang", "github.com/example", "core", "v1.2.3"}, {"composer", "example", "core", "1.2.3"}, {"gem", "", "example", "1.2.3"}, {"cargo", "", "example", "1.2.3"}} {
		name := c.name
		if c.eco == "pypi" {
			name = "demo-pkg"
		}
		if c.eco == "nuget" {
			name = "example.core"
		}
		if c.group != "" {
			name = c.group + "/" + name
		}
		obj := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []any{map[string]any{"name": c.name, "group": c.group, "version": c.version, "purl": "pkg:" + c.eco + "/" + name + "@" + c.version}}}
		b, _ := json.Marshal(obj)
		r, err := importFixture(t, string(b))
		if err != nil || len(r.Components) != 1 || len(r.Warnings) != 0 {
			t.Fatalf("%s: %+v %v", c.eco, r, err)
		}
	}
}
func TestImportRejectsConflictsAndMalformedInput(t *testing.T) {
	for _, input := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[null]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"core","group":"org.other","version":"1","purl":"pkg:maven/org.example/core@1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"core","group":"org.example","version":"2","purl":"pkg:maven/org.example/core@1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"core","group":"..","version":"1","purl":"pkg:maven/../core@1"}]}`,
	} {
		if _, err := importFixture(t, input); err == nil {
			t.Fatal("accepted malformed SBOM")
		}
	}
}
func TestImportCannotSilentlyDropUnsupportedOrIncompleteComponents(t *testing.T) {
	for _, component := range []string{`{"name":"unknown"}`, `{"name":"openssl","version":"1","purl":"pkg:apk/alpine/openssl@1"}`, `{"group":"org.example","name":"core","version":"1","purl":"pkg:maven/org.example/core@1?classifier=tests"}`, `{"name":"demo","purl":"pkg:pypi/demo"}`} {
		r, err := importFixture(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[`+component+`]}`)
		if err != nil || len(r.Warnings) == 0 {
			t.Fatal(r, err)
		}
	}
}
func TestImportFileBoundary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte(`{}`), 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if _, err := Import(context.Background(), link); err == nil {
		t.Fatal("symlink read")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Import(ctx, target); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestImportNestedPackageInsideFile(t *testing.T) {
	r, err := importFixture(t, `{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"file","name":"app.jar","components":[{"name":"core","group":"org.example","version":"1","purl":"pkg:maven/org.example/core@1"}]}]}`)
	if err != nil || len(r.Components) != 1 {
		t.Fatal(r, err)
	}
}
