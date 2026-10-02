package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
