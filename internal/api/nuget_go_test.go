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

	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
)

func TestNugetGoImportAndCheckPreserveIdentityAndUncertainty(t *testing.T) {
	for _, tc := range []struct{ ecosystem, name, version, purl, normalized string }{
		{"nuget", "System.Text.Json", "8.0.4", "pkg:nuget/System.Text.Json@8.0.4", "system.text.json"},
		{"go", "github.com/Example/Core/v2", "v2.0.0-rc.1+incompatible", "pkg:golang/github.com/Example/Core/v2@v2.0.0-rc.1%2Bincompatible", "github.com/Example/Core/v2"},
	} {
		t.Run(tc.ecosystem, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "external.json")
			data, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{map[string]string{"name": tc.name, "version": tc.version, "purl": tc.purl}}})
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := inventory.Import(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			data, err = inventory.Marshal(result, "demo", "test", time.Unix(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			normalized := filepath.Join(dir, "inventory.json")
			if err := os.WriteFile(normalized, data, 0600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := ReadSnapshot(context.Background(), normalized)
			if err != nil {
				t.Fatal(err)
			}
			c := snapshot.Components[0]
			if len(snapshot.Components) != 1 || c.Ecosystem != tc.ecosystem || c.Name != tc.normalized || c.Version != tc.version || c.Evidence != "imported-sbom" {
				t.Fatalf("identity changed: %+v", snapshot)
			}
			for _, precision := range []string{"version", "product"} {
				now := time.Now().UTC()
				gaps := []any{}
				if precision == "product" {
					gaps = append(gaps, map[string]any{"componentIndex": 0, "reason": "ADVISORY_RANGE_NOT_EVALUATED"})
				}
				report := map[string]any{"schemaVersion": 1, "status": "complete", "components": snapshot.Components,
					"coverage": map[string]any{"from": now.AddDate(-1, 0, 0).Format(time.RFC3339), "to": now.Format(time.RFC3339), "catalogGeneratedAt": now.Format(time.RFC3339), "inventoryCoverage": "complete", "componentsSubmitted": 1, "unevaluated": gaps},
					"matches":  []any{map[string]any{"cveId": "CVE-2026-999999", "components": []any{map[string]any{"componentIndex": 0, "precision": precision}}}}, "summary": map[string]int{"matchedCves": 1, "componentMatches": 1}}
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(report)
				}))
				client := NewClient(testCredentials(server.URL))
				client.http.Transport = server.Client().Transport
				if _, err := client.Check(context.Background(), snapshot); err != nil {
					t.Fatal(err)
				}
				server.Close()
			}
		})
	}
}
