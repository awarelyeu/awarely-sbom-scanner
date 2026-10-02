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
)

func testCredentials(origin string) Credentials {
	return Credentials{SchemaVersion: 1, APIURL: origin, Token: "awscan_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 43), ApplicationID: "app-a", SourceID: "source-a"}
}
func TestCredentialBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	c := testCredentials("https://api.example.invalid")
	b, _ := json.Marshal(c)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(context.Background(), path, nil); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0644)
	if _, err := ReadCredentials(context.Background(), path, nil); err == nil {
		t.Fatal("public credential file accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "symlink")
	os.Symlink(path, link)
	if _, err := ReadCredentials(context.Background(), link, nil); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, origin := range []string{"http://api.invalid", "https://user:pass@api.invalid", "https://api.invalid/path", "https://api.invalid?token=x", "https://api.invalid#x"} {
		c.APIURL = origin
		b, _ = json.Marshal(c)
		if _, err := ReadCredentials(context.Background(), "-", strings.NewReader(string(b))); err == nil {
			t.Fatal("unsafe origin accepted", origin)
		}
	}
	c = testCredentials("https://api.example.invalid")
	b, _ = json.Marshal(c)
	duplicated := strings.TrimSuffix(string(b), "}") + `,"token":"fake"}`
	if _, err := ReadCredentials(context.Background(), "-", strings.NewReader(duplicated)); err == nil {
		t.Fatal("duplicate field accepted")
	}
}
func TestRedirectAndTLSCannotLeakToken(t *testing.T) {
	received := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received++ }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c := NewClient(testCredentials(redirect.URL))
	c.http.Transport = redirect.Client().Transport
	if _, err := c.request(context.Background(), "POST", "/v1/asset-checks", []byte(`{}`), nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if received != 0 {
		t.Fatal("token forwarded")
	}
	untrusted := NewClient(testCredentials(target.URL))
	if _, err := untrusted.request(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if received != 0 {
		t.Fatal("untrusted endpoint reached")
	}
}
func TestSyncRetriesWithIdenticalRevisionAndIdempotencyKey(t *testing.T) {
	puts := 0
	var priorBody, priorKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			w.Write([]byte(`{"schemaVersion":1,"revision":"0","applicationId":"app-a","sourceId":"source-a"}`))
			return
		}
		if r.Method != "PUT" || r.Header.Get("If-Match") != "0" {
			t.Error("wrong method or revision")
		}
		var body json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		if puts == 0 {
			priorBody = string(body)
			priorKey = r.Header.Get("Idempotency-Key")
		} else if priorBody != string(body) || priorKey != r.Header.Get("Idempotency-Key") {
			t.Error("retry mutated request")
		}
		puts++
		if puts == 1 {
			w.WriteHeader(503)
			w.Write([]byte(`{"error":"RETRY"}`))
			return
		}
		w.Write([]byte(`{"schemaVersion":1,"status":"committed","applicationId":"app-a","sourceId":"source-a","revision":"11111111-1111-4111-8111-111111111111","sourceComponentCount":1}`))
	}))
	defer server.Close()
	client := NewClient(testCredentials(server.URL))
	client.http.Transport = server.Client().Transport
	snapshot := Snapshot{SchemaVersion: 1, CollectorVersion: "test", Coverage: "complete", Components: []Component{{Ecosystem: "npm", Name: "demo", Version: "1.0.0", Evidence: "resolved-lockfile"}}}
	if _, err := client.Sync(context.Background(), snapshot, "", "", false); err != nil {
		t.Fatal(err)
	}
	if puts != 2 || priorKey == "" {
		t.Fatal("idempotent retry missing")
	}
	snapshot.Coverage = "partial"
	if _, err := client.Sync(context.Background(), snapshot, "", "", false); err == nil {
		t.Fatal("partial sync accepted")
	}
	if puts != 2 {
		t.Fatal("partial inventory sent")
	}
}
func TestHostileOrOversizedResponseIsNotSuccess(t *testing.T) {
	for _, body := range []string{`{"schemaVersion":1,"schemaVersion":1}`, strings.Repeat("x", MaxResponse+1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(body))
		}))
		c := NewClient(testCredentials(server.URL))
		c.http.Transport = server.Client().Transport
		if _, err := c.request(context.Background(), "GET", "/", nil, nil); err == nil {
			t.Fatal("hostile response accepted")
		}
		server.Close()
	}
}
func TestProjectionDoesNotSendProjectMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.json")
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"properties":[{"name":"awarely:coverage","value":"complete-for-selected-inputs"}],"private":"SECRET"},"components":[{"type":"library","name":"@aws-sdk/core","version":"3.1.0","purl":"pkg:npm/%40aws-sdk/core@3.1.0","externalReferences":[{"url":"https://token:SECRET@registry.invalid"}],"properties":[{"name":"awarely:evidence","value":"resolved-lockfile"}]}]}`
	os.WriteFile(path, []byte(bom), 0600)
	s, err := ReadSnapshot(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "registry.invalid") {
		t.Fatal("metadata leaked")
	}
	if s.Components[0].Name != "@aws-sdk/core" {
		t.Fatal(s)
	}
}

func TestCheckRequiresCompleteConsistentEvidence(t *testing.T) {
	snapshot := Snapshot{SchemaVersion: 1, CollectorVersion: "test", Coverage: "complete", Components: []Component{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", Evidence: "resolved-lockfile"}}}
	valid := map[string]any{"schemaVersion": 1, "status": "complete", "components": snapshot.Components, "coverage": map[string]any{"from": "2025-01-01T00:00:00Z", "to": "2026-01-01T00:00:00Z", "catalogGeneratedAt": "2026-01-01T00:00:00Z", "inventoryCoverage": "complete", "componentsSubmitted": 1}, "matches": []any{map[string]any{"cveId": "CVE-2025-12345", "components": []any{map[string]any{"componentIndex": 0, "precision": "version"}}}}, "summary": map[string]any{"matchedCves": 1, "componentMatches": 1}}
	original, _ := json.Marshal(valid)
	for _, mutation := range []func(map[string]any){nil, func(v map[string]any) { delete(v, "coverage") }, func(v map[string]any) { v["summary"] = map[string]any{"matchedCves": 0} }, func(v map[string]any) {
		v["matches"] = []any{map[string]any{"cveId": "CVE-2025-12345", "components": []any{map[string]any{"componentIndex": 9, "precision": "version"}}}}
	}} {
		var value map[string]any
		json.Unmarshal(original, &value)
		if mutation != nil {
			mutation(value)
		}
		body, _ := json.Marshal(value)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		}))
		c := NewClient(testCredentials(server.URL))
		c.http.Transport = server.Client().Transport
		_, err := c.Check(context.Background(), snapshot)
		if (mutation == nil) != (err == nil) {
			t.Fatalf("unexpected validation result: %v", err)
		}
		server.Close()
	}
}
