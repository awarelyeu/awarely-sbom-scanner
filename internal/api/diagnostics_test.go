package api

import (
	"bytes"
	"context"
	"errors"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/diagnostics"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteDiagnosticsAllowlist(t *testing.T) {
	for _, code := range []string{"INSUFFICIENT_SCOPE", "ATTACKER_SECRET", "SECRET\u001b[31m"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			if code == "INSUFFICIENT_SCOPE" {
				w.Write([]byte(`{"error":"INSUFFICIENT_SCOPE"}`))
			} else {
				w.Write([]byte(`{"error":"ATTACKER_SECRET"}`))
			}
		}))
		client := NewClient(Credentials{APIURL: server.URL})
		client.http = server.Client()
		var out bytes.Buffer
		ctx := diagnostics.With(context.Background(), &out, diagnostics.Options{Format: "events"})
		_, err := client.request(ctx, "GET", "/", nil, nil)
		server.Close()
		var remote *RemoteError
		if !errors.As(err, &remote) {
			t.Fatal(err)
		}
		Diagnose(ctx, err)
		expected := "REQUEST_REJECTED"
		if code == "INSUFFICIENT_SCOPE" {
			expected = code
		}
		if !strings.Contains(out.String(), "AWARELY_ERROR_V1 "+expected) || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("unsafe or incorrect diagnostic %v %q", err, out.String())
		}
	}
}
