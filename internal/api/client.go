package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const MaxResponse = 5 << 20

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var tokenPattern = regexp.MustCompile(`^awscan_[a-f0-9]{32}_[A-Za-z0-9_-]{43}$`)

type Credentials struct {
	SchemaVersion int    `json:"schemaVersion"`
	APIURL        string `json:"apiUrl"`
	Token         string `json:"token"`
	ApplicationID string `json:"applicationId"`
	SourceID      string `json:"sourceId"`
}

func ReadCredentials(ctx context.Context, path string, stdin io.Reader) (Credentials, error) {
	var c Credentials
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, 8193))
	} else {
		root, e := os.OpenRoot(filepath.Dir(path))
		if e != nil {
			return c, errors.New("cannot open credential directory")
		}
		defer root.Close()
		info, e := root.Lstat(filepath.Base(path))
		if e != nil {
			return c, errors.New("cannot read credentials")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0077 != 0 {
			return c, errors.New("credential file must belong to this user and have owner-only permissions (chmod 600)")
		}
		b, err = safeio.ReadPrivateRegular(ctx, root, filepath.Base(path), 8192)
	}
	if err != nil || len(b) > 8192 {
		return c, errors.New("cannot safely read credentials")
	}
	if inventory.ValidateJSON(ctx, b) != nil {
		return c, errors.New("invalid credential JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.SchemaVersion != 1 || !tokenPattern.MatchString(c.Token) || !idPattern.MatchString(c.ApplicationID) || !idPattern.MatchString(c.SourceID) {
		return Credentials{}, errors.New("invalid credentials")
	}
	u, e := url.Parse(c.APIURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return Credentials{}, errors.New("credentials require an HTTPS API origin without userinfo, path or query")
	}
	c.APIURL = strings.TrimSuffix(c.APIURL, "/")
	return c, nil
}

type Client struct {
	credentials Credentials
	http        *http.Client
}

func NewClient(c Credentials) *Client {
	return &Client{c, &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 25 * time.Second, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, MaxIdleConnsPerHost: 1}}}
}
func (c *Client) request(ctx context.Context, method, path string, body []byte, headers map[string]string) ([]byte, error) {
	if len(body) > 2<<20 {
		return nil, errors.New("normalized inventory exceeds API limit")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			var jitter [1]byte
			if _, err := rand.Read(jitter[:]); err != nil {
				return nil, errors.New("cannot schedule retry")
			}
			timer := time.NewTimer(time.Duration(250*(1<<attempt)+int(jitter[0])) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.credentials.APIURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("invalid API request")
		}
		req.Header.Set("Authorization", "Bearer "+c.credentials.Token)
		req.Header.Set("Accept", "application/json")
		if method != "GET" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < 2 {
				continue
			}
			return nil, errors.New("API transport failed; credentials and response details were not logged")
		}
		b, readErr := io.ReadAll(io.LimitReader(response.Body, MaxResponse+1))
		response.Body.Close()
		if readErr != nil || len(b) > MaxResponse {
			return nil, errors.New("API response exceeds limit or is incomplete")
		}
		if response.StatusCode == 503 && attempt < 2 {
			continue
		}
		if response.StatusCode != 200 {
			code := "REQUEST_REJECTED"
			var message struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(b, &message) == nil && regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`).MatchString(message.Error) {
				code = message.Error
			}
			return nil, fmt.Errorf("API returned HTTP %d (%s)", response.StatusCode, code)
		}
		if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") || response.Header.Get("Content-Encoding") != "" {
			return nil, errors.New("API returned unsupported content")
		}
		if inventory.ValidateJSON(ctx, b) != nil {
			return nil, errors.New("API returned invalid or overly complex JSON")
		}
		return b, nil
	}
	return nil, errors.New("API unavailable")
}
func (c *Client) Check(ctx context.Context, s Snapshot) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	result, err := c.request(ctx, "POST", "/v1/asset-checks", b, nil)
	if err != nil {
		return nil, err
	}
	var check struct {
		Schema     int         `json:"schemaVersion"`
		Status     string      `json:"status"`
		Components []Component `json:"components"`
		Matches    []struct {
			CVEID      string `json:"cveId"`
			Components []struct {
				Index     int    `json:"componentIndex"`
				Precision string `json:"precision"`
			} `json:"components"`
		} `json:"matches"`
		Coverage struct {
			From        string `json:"from"`
			To          string `json:"to"`
			Catalog     string `json:"catalogGeneratedAt"`
			Inventory   string `json:"inventoryCoverage"`
			Submitted   int    `json:"componentsSubmitted"`
			Unevaluated []struct {
				Index  int    `json:"componentIndex"`
				Reason string `json:"reason"`
			} `json:"unevaluated"`
		} `json:"coverage"`
		Summary struct {
			CVEs       int `json:"matchedCves"`
			Components int `json:"componentMatches"`
		} `json:"summary"`
	}
	invalid := errors.New("API did not return a complete, consistent check result")
	if json.Unmarshal(result, &check) != nil || check.Schema != 1 || check.Status != "complete" || check.Matches == nil || len(check.Components) != len(s.Components) || check.Coverage.Submitted != len(s.Components) || check.Summary.CVEs != len(check.Matches) {
		return nil, invalid
	}
	from, fromErr := time.Parse(time.RFC3339Nano, check.Coverage.From)
	to, toErr := time.Parse(time.RFC3339Nano, check.Coverage.To)
	_, catalogErr := time.Parse(time.RFC3339Nano, check.Coverage.Catalog)
	if fromErr != nil || toErr != nil || catalogErr != nil || !from.Before(to) || (check.Coverage.Inventory != "partial" && check.Coverage.Inventory != "complete") || (s.Coverage == "partial" && check.Coverage.Inventory != "partial") {
		return nil, invalid
	}
	seen := map[string]bool{}
	componentMatches := 0
	for _, match := range check.Matches {
		if !regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}|GHSA-[A-Za-z0-9-]{14})$`).MatchString(match.CVEID) || seen[match.CVEID] || len(match.Components) == 0 {
			return nil, invalid
		}
		seen[match.CVEID] = true
		indices := map[int]bool{}
		for _, c := range match.Components {
			if c.Index < 0 || c.Index >= len(s.Components) || indices[c.Index] || (c.Precision != "version" && c.Precision != "product") || (s.Components[c.Index].Ecosystem == "deb" && c.Precision == "version") {
				return nil, invalid
			}
			indices[c.Index] = true
			componentMatches++
		}
	}
	if componentMatches != check.Summary.Components {
		return nil, invalid
	}
	unevaluated := map[int]bool{}
	for _, c := range check.Coverage.Unevaluated {
		if c.Index < 0 || c.Index >= len(s.Components) || unevaluated[c.Index] || c.Reason == "" {
			return nil, invalid
		}
		unevaluated[c.Index] = true
	}
	for i, c := range s.Components {
		if (c.Ecosystem == "deb" || c.Version == "") && !unevaluated[i] {
			return nil, invalid
		}
	}
	want, _ := json.Marshal(s.Components)
	got, _ := json.Marshal(check.Components)
	if !bytes.Equal(want, got) {
		return nil, errors.New("API result does not describe submitted components")
	}
	return result, nil
}
func (c *Client) Sync(ctx context.Context, s Snapshot, revision, key string, allowEmpty bool) ([]byte, error) {
	if s.Coverage != "complete" {
		return nil, errors.New("sync requires complete coverage; review the local SBOM warnings")
	}
	if len(s.Components) == 0 && !allowEmpty {
		return nil, errors.New("empty sync requires --allow-empty")
	}
	path := "/v1/applications/" + c.credentials.ApplicationID + "/sources/" + c.credentials.SourceID + "/inventory"
	if revision == "" {
		b, err := c.request(ctx, "GET", path, nil, nil)
		if err != nil {
			return nil, err
		}
		var state struct {
			Schema        int    `json:"schemaVersion"`
			Revision      string `json:"revision"`
			ApplicationID string `json:"applicationId"`
			SourceID      string `json:"sourceId"`
		}
		if json.Unmarshal(b, &state) != nil || state.Schema != 1 || state.ApplicationID != c.credentials.ApplicationID || state.SourceID != c.credentials.SourceID {
			return nil, errors.New("invalid source response")
		}
		revision = state.Revision
	}
	if !regexp.MustCompile(`^(0|[a-f0-9-]{36})$`).MatchString(revision) {
		return nil, errors.New("invalid source revision")
	}
	if key == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		key = hex.EncodeToString(nonce[:])
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`).MatchString(key) {
		return nil, errors.New("invalid idempotency key")
	}
	headers := map[string]string{"If-Match": revision, "Idempotency-Key": key}
	if allowEmpty {
		headers["X-Awarely-Allow-Empty"] = "true"
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	result, err := c.request(ctx, "PUT", path, b, headers)
	if err != nil {
		return nil, err
	}
	var state struct {
		Schema        int    `json:"schemaVersion"`
		Status        string `json:"status"`
		SourceID      string `json:"sourceId"`
		ApplicationID string `json:"applicationId"`
		Revision      string `json:"revision"`
		Count         int    `json:"sourceComponentCount"`
	}
	if json.Unmarshal(result, &state) != nil || state.Schema != 1 || state.Status != "committed" || state.SourceID != c.credentials.SourceID || state.ApplicationID != c.credentials.ApplicationID || state.Count != len(s.Components) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(state.Revision) {
		return nil, errors.New("API did not confirm this inventory commit")
	}
	return result, nil
}
