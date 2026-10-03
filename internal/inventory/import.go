package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

// Import reads a selected SBOM, not a project or archive. Only allowlisted
// package identity fields survive; URLs, file paths and arbitrary properties
// from the producer are neither followed nor forwarded to the service.
func Import(ctx context.Context, path string) (Result, error) {
	r := Result{Scope: "imported-sbom", Inputs: []string{"CycloneDX JSON"}}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return r, errors.New("cannot open SBOM directory")
	}
	defer root.Close()
	data, err := safeio.ReadRegular(ctx, root, filepath.Base(path), MaxManifestBytes)
	if err != nil {
		return r, errors.New("cannot safely read SBOM")
	}
	if err = ValidateJSON(ctx, data); err != nil {
		return r, err
	}
	type entry struct {
		Type       string            `json:"type"`
		Name       string            `json:"name"`
		Group      string            `json:"group"`
		Version    string            `json:"version"`
		PURL       string            `json:"purl"`
		Components []json.RawMessage `json:"components"`
	}
	var bom struct {
		Format     string            `json:"bomFormat"`
		Spec       string            `json:"specVersion"`
		Components []json.RawMessage `json:"components"`
		Metadata   struct {
			Properties []Property `json:"properties"`
		} `json:"metadata"`
		Compositions []struct {
			Aggregate string `json:"aggregate"`
		} `json:"compositions"`
	}
	if json.Unmarshal(data, &bom) != nil || bom.Format != "CycloneDX" || (bom.Spec != "1.4" && bom.Spec != "1.5" && bom.Spec != "1.6" && bom.Spec != "1.7") || bom.Components == nil {
		return r, errors.New("expected CycloneDX JSON 1.4–1.7 with a components array")
	}
	for _, p := range bom.Metadata.Properties {
		if p.Name == "awarely:coverage" && p.Value != "complete-for-selected-inputs" {
			r.Warn("INPUT_DECLARED_PARTIAL")
		}
	}
	for _, c := range bom.Compositions {
		if c.Aggregate != "complete" && c.Aggregate != "not_specified" {
			r.Warn("INPUT_DECLARED_INCOMPLETE")
		}
	}
	count := 0
	var visit func([]json.RawMessage) error
	visit = func(entries []json.RawMessage) error {
		for _, raw := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			count++
			if count > MaxComponents {
				return errors.New("SBOM component limit exceeded")
			}
			var c entry
			if json.Unmarshal(raw, &c) != nil || c.Name == "" {
				return errors.New("invalid SBOM component")
			}
			if err := visit(c.Components); err != nil {
				return err
			}
			if c.Type == "file" {
				continue
			}
			if !strings.HasPrefix(c.PURL, "pkg:") || strings.Contains(c.PURL, "#") {
				r.Warn("COMPONENT_WITHOUT_SUPPORTED_PURL")
				continue
			}
			body, query, _ := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "?")
			eco, identity, ok := strings.Cut(body, "/")
			if !ok {
				return errors.New("invalid package URL")
			}
			if !strings.Contains("|npm|pypi|maven|nuget|golang|composer|gem|cargo|", "|"+eco+"|") {
				r.Warn("UNSUPPORTED_ECOSYSTEM")
				continue
			}
			at := strings.LastIndex(identity, "@")
			version := ""
			if at > 0 {
				version, err = url.PathUnescape(identity[at+1:])
				if err != nil {
					return rError()
				}
				identity = identity[:at]
			}
			name, err := url.PathUnescape(identity)
			if err != nil {
				return rError()
			}
			q, err := url.ParseQuery(query)
			if err != nil {
				return rError()
			}
			// Maven's default packaging is not a separate vulnerability coordinate.
			// Classifiers/custom variants need explicit support rather than being lost.
			if len(q) != 0 && !(eco == "maven" && len(q) == 1 && len(q["type"]) == 1 && (q.Get("type") == "jar" || q.Get("type") == "pom" || q.Get("type") == "war" || q.Get("type") == "ear")) {
				r.Warn("UNSUPPORTED_PACKAGE_VARIANT")
				continue
			}
			expected := c.Name
			if c.Group != "" {
				expected = c.Group + "/" + c.Name
			}
			if eco == "pypi" {
				expected = pyNormalize.ReplaceAllString(strings.ToLower(expected), "-")
				name = pyNormalize.ReplaceAllString(strings.ToLower(name), "-")
			}
			if eco == "nuget" {
				expected = strings.ToLower(expected)
				name = strings.ToLower(name)
			}
			if eco == "maven" && c.Group == "" && strings.HasSuffix(name, "/"+c.Name) {
				expected = name
			}
			if name != expected || version != c.Version {
				return errors.New("SBOM component disagrees with its package URL")
			}
			component, err := NewComponent(eco, name, version, "imported-sbom", nil)
			if err != nil {
				return err
			}
			if version == "" {
				r.Warn("VERSION_UNKNOWN")
			}
			if err := r.Add(component); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(bom.Components); err != nil {
		return Result{}, err
	}
	r.Notices = append(r.Notices, "IMPORTED_SBOM: coverage describes the selected file, not deployment completeness or producer authenticity")
	return r, nil
}
func rError() error { return errors.New("invalid package URL") }
