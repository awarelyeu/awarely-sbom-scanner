package inventory

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxComponents = 5000
const MaxManifestBytes = 5 << 20
const MaxOutputBytes = 5 << 20

// Legacy npm packages may contain uppercase letters; PURL identities preserve case.
var npmName = regexp.MustCompile(`^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)
var pythonName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var debName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
var versionText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.!+:~_^\-]*$`)
var npmVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$`)
var pyNormalize = regexp.MustCompile(`[-_.]+`)

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Component struct {
	Type       string     `json:"type"`
	Ref        string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}
type Result struct {
	Components []Component
	Warnings   []string
	Inputs     []string
	Scope      string
	seen       map[string]int
}

func (r *Result) Warn(code string) {
	for _, c := range r.Warnings {
		if c == code {
			return
		}
	}
	r.Warnings = append(r.Warnings, code)
}
func (r *Result) Add(c Component) error {
	if r.seen == nil {
		r.seen = map[string]int{}
	}
	if index, exists := r.seen[c.Ref]; exists {
		for _, p := range c.Properties {
			found := false
			for _, prior := range r.Components[index].Properties {
				if p == prior {
					found = true
					break
				}
			}
			if !found {
				r.Components[index].Properties = append(r.Components[index].Properties, p)
			}
		}
		return nil
	}
	if len(r.Components) >= MaxComponents {
		return errors.New("component limit exceeded; no inventory was written")
	}
	r.seen[c.Ref] = len(r.Components)
	r.Components = append(r.Components, c)
	return nil
}
func ValidText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) || unicode.In(c, unicode.Cf) {
			return false
		}
	}
	return true
}
func NewComponent(ecosystem, name, version, evidence string, qualifiers url.Values) (Component, error) {
	valid := false
	switch ecosystem {
	case "npm":
		valid = npmName.MatchString(name)
	case "pypi":
		valid = pythonName.MatchString(name)
		name = pyNormalize.ReplaceAllString(strings.ToLower(name), "-")
	case "rpm":
		valid = rpmName.MatchString(name)
	case "deb":
		valid = debName.MatchString(name)
	}
	if !valid || !ValidText(name, 200) || (version != "" && (!ValidText(version, 100) || !versionText.MatchString(version))) {
		return Component{}, errors.New("invalid package identity")
	}
	if ecosystem == "npm" && version != "" && !npmVersion.MatchString(version) {
		return Component{}, errors.New("npm package version is not an exact release")
	}
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(p), "@", "%40")
	}
	purl := "pkg:" + ecosystem + "/" + strings.Join(parts, "/")
	if (ecosystem == "deb" || ecosystem == "rpm") && qualifiers.Get("distro") != "" {
		purl = "pkg:" + ecosystem + "/" + url.PathEscape(strings.SplitN(qualifiers.Get("distro"), "-", 2)[0]) + "/" + url.PathEscape(name)
	}
	if version != "" {
		purl += "@" + url.PathEscape(version)
	}
	if len(qualifiers) > 0 {
		purl += "?" + strings.ReplaceAll(qualifiers.Encode(), "+", "%20")
	}
	return Component{Type: "library", Ref: purl, Name: name, Version: version, PURL: purl, Properties: []Property{{"awarely:evidence", evidence}}}, nil
}

func Marshal(r Result, app, version string, now time.Time) ([]byte, error) {
	if !ValidText(app, 120) {
		return nil, errors.New("application name must be 1–120 bytes without control characters")
	}
	r.Components = append([]Component(nil), r.Components...)
	for i := range r.Components {
		r.Components[i].Properties = append([]Property(nil), r.Components[i].Properties...)
	}
	sort.Slice(r.Components, func(i, j int) bool { return r.Components[i].Ref < r.Components[j].Ref })
	for i := range r.Components {
		sort.Slice(r.Components[i].Properties, func(a, b int) bool {
			x, y := r.Components[i].Properties[a], r.Components[i].Properties[b]
			if x.Name == y.Name {
				return x.Value < y.Value
			}
			return x.Name < y.Name
		})
	}
	r.Warnings = append([]string(nil), r.Warnings...)
	r.Inputs = append([]string(nil), r.Inputs...)
	sort.Strings(r.Warnings)
	sort.Strings(r.Inputs)
	state := "complete-for-selected-inputs"
	if len(r.Warnings) > 0 {
		state = "partial"
	}
	props := []Property{{"awarely:mode", "local"}, {"awarely:coverage", state}, {"awarely:scope", r.Scope}, {"awarely:inputs", strings.Join(r.Inputs, ",")}, {"awarely:network", "disabled"}}
	for _, w := range r.Warnings {
		props = append(props, Property{"awarely:warning", w})
	}
	if r.Components == nil {
		r.Components = []Component{}
	}
	bom := struct {
		Format       string      `json:"bomFormat"`
		Spec         string      `json:"specVersion"`
		Version      int         `json:"version"`
		Metadata     any         `json:"metadata"`
		Components   []Component `json:"components"`
		Compositions any         `json:"compositions"`
	}{"CycloneDX", "1.6", 1, map[string]any{
		"timestamp": now.UTC().Format(time.RFC3339),
		"tools":     map[string]any{"components": []any{map[string]any{"type": "application", "name": "awarely-scan", "version": version}}},
		"component": map[string]any{"type": "application", "name": app}, "properties": props,
	}, r.Components, []any{map[string]any{"aggregate": "incomplete"}}}
	b, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(b) > MaxOutputBytes {
		return nil, errors.New("output exceeds the supported size limit")
	}
	return append(b, '\n'), nil
}
