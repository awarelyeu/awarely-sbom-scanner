package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDistributionCheckRequiresAccountedCoverageAndEvidence(t *testing.T) {
	component := Component{Ecosystem: "deb", Name: "libssl3", Version: "3.0.13-1", Evidence: "installed-dpkg", Distribution: "ubuntu", DistributionVersion: "24.04", Architecture: "amd64", SourcePackage: "openssl", SourceVersion: "3.0.13-1"}
	snapshot := Snapshot{SchemaVersion: 1, CollectorVersion: "test", Coverage: "complete", Components: []Component{component}}
	now := time.Now().UTC()
	for _, mutate := range []func(map[string]any){nil,
		func(r map[string]any) { r["coverage"].(map[string]any)["distributionEvaluated"] = []any{} },
		func(r map[string]any) {
			r["matches"].([]any)[0].(map[string]any)["components"].([]any)[0].(map[string]any)["distributionEvidence"] = []any{}
		},
		func(r map[string]any) {
			r["matches"].([]any)[0].(map[string]any)["components"].([]any)[0].(map[string]any)["distributionEvidence"].([]any)[0].(map[string]any)["sourcePackage"] = "different"
		},
		func(r map[string]any) {
			r["matches"].([]any)[0].(map[string]any)["components"].([]any)[0].(map[string]any)["distributionEvidence"].([]any)[0].(map[string]any)["status"] = "under-investigation"
		},
	} {
		evidence := map[string]any{"source": "UBUNTU", "distribution": "ubuntu", "release": "24.04", "sourcePackage": "openssl", "sourceVersion": "3.0.13-1", "versionScheme": "dpkg", "status": "affected", "catalogGeneratedAt": now.Format(time.RFC3339)}
		result := map[string]any{"schemaVersion": 1, "status": "complete", "components": snapshot.Components, "summary": map[string]int{"matchedCves": 1, "componentMatches": 1},
			"matches": []any{map[string]any{"cveId": "CVE-2024-12345", "components": []any{map[string]any{"componentIndex": 0, "precision": "version", "distributionEvidence": []any{evidence}}}}},
			"coverage": map[string]any{"from": now.AddDate(-1, 0, 0).Format(time.RFC3339), "to": now.Format(time.RFC3339), "catalogGeneratedAt": now.Format(time.RFC3339), "inventoryCoverage": "complete", "componentsSubmitted": 1, "unevaluated": []any{},
				"distributionEvaluated": []any{map[string]any{"componentIndex": 0, "release": "ubuntu-24.04", "source": "UBUNTU", "versionScheme": "dpkg", "catalogGeneratedAt": now.Format(time.RFC3339)}}}}
		if mutate != nil {
			mutate(result)
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		}))
		client := NewClient(testCredentials(server.URL))
		client.http.Transport = server.Client().Transport
		_, err := client.Check(context.Background(), snapshot)
		if (mutate == nil) != (err == nil) {
			t.Fatalf("unexpected validation result: %v", err)
		}
		server.Close()
	}
}

func TestSnapshotPreservesSourceIdentityAndRejectsAmbiguity(t *testing.T) {
	const prefix = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"libssl3","version":"3.0.13-1+b1","purl":"pkg:deb/ubuntu/libssl3@3.0.13-1+b1?arch=amd64&distro=ubuntu-24.04","properties":[{"name":"awarely:evidence","value":"installed-dpkg"},`
	for _, tail := range []string{
		`{"name":"awarely:source-package","value":"openssl"},{"name":"awarely:source-version","value":"3.0.13-1"}`,
		`{"name":"awarely:source-package","value":"openssl"}`,
		`{"name":"awarely:source-package","value":"openssl"},{"name":"awarely:source-package","value":"fake"},{"name":"awarely:source-version","value":"3.0.13-1"}`,
	} {
		p := filepath.Join(t.TempDir(), "inventory.cdx.json")
		os.WriteFile(p, []byte(prefix+tail+`]}]}`), 0600)
		snapshot, err := ReadSnapshot(context.Background(), p)
		if tail == `{"name":"awarely:source-package","value":"openssl"},{"name":"awarely:source-version","value":"3.0.13-1"}` {
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Components[0].SourceVersion != "3.0.13-1" {
				t.Fatal("lost binNMU source version")
			}
		} else if err == nil {
			t.Fatal("ambiguous metadata accepted")
		}
	}
}

func TestRPMSnapshotPreservesVendorModuleAndRejectsSpoofedMetadata(t *testing.T) {
	const source = `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"properties":[{"name":"awarely:coverage","value":"complete-for-selected-inputs"}]},"components":[{"name":"nodejs","version":"1:20.1-1.module+el9.3+123+abc","purl":"pkg:rpm/rocky/nodejs@1:20.1-1.module+el9.3+123+abc?arch=x86_64&distro=rocky-9.3","properties":[{"name":"awarely:evidence","value":"installed-rpm"},{"name":"awarely:rpm-vendor","value":"Rocky Enterprise Software Foundation"},{"name":"awarely:rpm-module","value":"nodejs:20:9001:rhel9"},{"name":"awarely:source-package","value":"nodejs"},{"name":"awarely:source-version","value":"20.1-1.module+el9.3+123+abc"}]}]}`
	path := filepath.Join(t.TempDir(), "rpm.json")
	os.WriteFile(path, []byte(source), 0600)
	s, e := ReadSnapshot(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	if s.Coverage != "complete" || s.Components[0].RPMModule != "nodejs:20:9001:rhel9" || s.Components[0].RPMVendor != "Rocky Enterprise Software Foundation" || s.Components[0].SourceVersion != "20.1-1.module+el9.3+123+abc" {
		t.Fatalf("lost RPM metadata: %+v", s)
	}
	for _, bad := range []string{strings.Replace(source, "pkg:rpm/rocky/", "pkg:rpm/ubuntu/", 1), strings.Replace(source, "\"awarely:source-package\"", "\"awarely:rpm-module\"", 1), strings.Replace(source, "arch=x86_64", "arch=x86_64&arch=aarch64", 1)} {
		os.WriteFile(path, []byte(bad), 0600)
		if _, e := ReadSnapshot(context.Background(), path); e == nil {
			t.Fatal("ambiguous RPM identity accepted")
		}
	}
}

func TestAmazonLinuxSnapshotKeepsNativeRPMIdentity(t *testing.T) {
	for _, release := range []string{"2", "2023"} {
		c := map[string]any{"name": "openssl-libs", "version": "1:3.2.2-1.amzn" + release + ".0.1", "purl": "pkg:rpm/amzn/openssl-libs@1:3.2.2-1.amzn" + release + ".0.1?arch=aarch64&distro=amzn-" + release, "properties": []map[string]string{{"name": "awarely:evidence", "value": "installed-rpm"}, {"name": "awarely:rpm-vendor", "value": "Amazon Linux"}}}
		b, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{c}})
		p := filepath.Join(t.TempDir(), "amzn.json")
		os.WriteFile(p, b, 0600)
		got, err := ReadSnapshot(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		if got.Components[0].Distribution != "amzn" || got.Components[0].DistributionVersion != release || got.Components[0].RPMVendor != "Amazon Linux" {
			t.Fatal("Amazon evidence lost")
		}
	}
}
