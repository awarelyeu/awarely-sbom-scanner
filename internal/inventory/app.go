package inventory

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

func App(ctx context.Context, path string) (Result, error) {
	return AppFor(ctx, path, "")
}

// AppFor limits a guided selection to one ecosystem. An empty ecosystem keeps
// the established app command's combined manifest behavior.
func AppFor(ctx context.Context, path, ecosystem string) (Result, error) {
	r := Result{Scope: "selected-directory-manifests; no recursion; no installed-package claim"}
	if ecosystem != "" && ecosystem != "npm" && ecosystem != "python" {
		return r, errors.New("unsupported native application ecosystem")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return r, errors.New("cannot open selected application directory")
	}
	defer root.Close()
	foundNPM := false
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json", "package.json"} {
		if ecosystem == "python" {
			break
		}
		b, err := safeio.ReadRegular(ctx, root, name, MaxManifestBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return r, errors.New("cannot safely read " + name)
		}
		if name == "package.json" {
			err = ParsePackageJSON(ctx, b, &r)
		} else {
			err = ParseLock(ctx, b, &r)
		}
		if err != nil {
			return r, err
		}
		r.Inputs = append(r.Inputs, name)
		foundNPM = true
		break
	}
	if ecosystem != "npm" {
		b, err := safeio.ReadRegular(ctx, root, "requirements.txt", MaxManifestBytes)
		if err == nil {
			if err = ParseRequirements(ctx, b, &r); err != nil {
				return r, err
			}
			r.Inputs = append(r.Inputs, "requirements.txt")
		} else if !errors.Is(err, os.ErrNotExist) {
			return r, errors.New("cannot safely read requirements.txt")
		}
	}
	if !foundNPM && len(r.Inputs) == 0 {
		return r, errors.New("no supported manifest found; select a directory containing package-lock.json, npm-shrinkwrap.json, package.json or requirements.txt")
	}
	if len(r.Components) == 0 {
		r.Warn("NO_COMPONENTS_FOUND")
	}
	return r, ctx.Err()
}

func ParseLock(ctx context.Context, b []byte, r *Result) error {
	if err := ValidateJSON(ctx, b); err != nil {
		return err
	}
	var lock struct {
		LockfileVersion int                        `json:"lockfileVersion"`
		Packages        map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil || lock.Packages == nil || (lock.LockfileVersion != 2 && lock.LockfileVersion != 3) {
		return errors.New("only npm lockfile versions 2 and 3 are supported")
	}
	if len(lock.Packages) > 50000 {
		return errors.New("too many lockfile entries")
	}
	for path, raw := range lock.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == "" {
			continue
		}
		var p struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Link     bool   `json:"link"`
			Dev      bool   `json:"dev"`
			Optional bool   `json:"optional"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || string(raw) == "null" {
			return errors.New("invalid npm lockfile entry")
		}
		if p.Link {
			r.Warn("WORKSPACE_LINKS_NOT_FOLLOWED")
			continue
		}
		if !strings.HasPrefix(path, "node_modules/") || strings.Contains(path, "\\") || strings.Contains(path, "/../") {
			r.Warn("LOCAL_WORKSPACE_PACKAGES_NOT_INCLUDED")
			continue
		}
		name := p.Name
		if name == "" {
			idx := strings.LastIndex(path, "node_modules/")
			name = path[idx+len("node_modules/"):]
		}
		if p.Version == "" {
			r.Warn("PACKAGES_WITHOUT_EXACT_VERSION")
			continue
		}
		c, err := NewComponent("npm", name, p.Version, "resolved-lockfile", nil)
		if err != nil {
			return err
		}
		if p.Dev {
			c.Properties = append(c.Properties, Property{"awarely:used-in-development", "true"})
		} else {
			c.Properties = append(c.Properties, Property{"awarely:used-at-runtime", "true"})
		}
		if p.Optional {
			c.Properties = append(c.Properties, Property{"awarely:optional", "true"})
		}
		if err = r.Add(c); err != nil {
			return err
		}
	}
	return nil
}

func ParsePackageJSON(ctx context.Context, b []byte, r *Result) error {
	if err := ValidateJSON(ctx, b); err != nil {
		return err
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(b, &pkg); err != nil || pkg == nil {
		return errors.New("invalid package.json")
	}
	r.Warn("MANIFEST_ONLY_TRANSITIVE_DEPENDENCIES_UNKNOWN")
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		raw, ok := pkg[field]
		if !ok {
			continue
		}
		var deps map[string]string
		if err := json.Unmarshal(raw, &deps); err != nil || deps == nil {
			return errors.New("invalid dependency declarations")
		}
		for name, spec := range deps {
			if err := ctx.Err(); err != nil {
				return err
			}
			if strings.HasPrefix(spec, "npm:") {
				alias := strings.TrimPrefix(spec, "npm:")
				at := strings.LastIndex(alias, "@")
				if at <= 0 {
					r.Warn("UNRESOLVED_DEPENDENCY_SPEC")
					continue
				}
				name, spec = alias[:at], alias[at+1:]
			}
			version := ""
			if npmVersion.MatchString(spec) {
				version = spec
			} else {
				r.Warn("DECLARED_VERSION_NOT_EXACT")
			}
			// Never export a URL, local path or credential-bearing dependency spec.
			c, err := NewComponent("npm", name, version, "declared-manifest", nil)
			if err != nil {
				return err
			}
			if err = r.Add(c); err != nil {
				return err
			}
		}
	}
	return nil
}

var requirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.*)$`)
var pyVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.!+_-]*$`)
var requirementSpec = regexp.MustCompile(`^(?:===|==|!=|<=|>=|~=|<|>)\s*[A-Za-z0-9.!+_*-]+\s*(?:,\s*(?:===|==|!=|<=|>=|~=|<|>)\s*[A-Za-z0-9.!+_*-]+\s*)*$`)

func ParseRequirements(ctx context.Context, b []byte, r *Result) error {
	if len(b) > MaxManifestBytes || !utf8.Valid(b) {
		return errors.New("invalid or oversized requirements.txt")
	}
	r.Warn("REQUIREMENTS_TRANSITIVE_DEPENDENCIES_UNKNOWN")
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 4096), 64<<10)
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			r.Warn("REQUIREMENTS_DIRECTIVES_NOT_FOLLOWED")
			continue
		}
		if strings.Contains(line, "\\") {
			r.Warn("REQUIREMENTS_CONTINUATIONS_NOT_SUPPORTED")
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			r.Warn("ENVIRONMENT_MARKERS_NOT_EVALUATED")
		}
		m := requirement.FindStringSubmatch(line)
		if m == nil {
			r.Warn("UNSUPPORTED_REQUIREMENT")
			continue
		}
		spec := strings.TrimSpace(m[2])
		if strings.Contains(spec, "@") {
			r.Warn("DIRECT_REFERENCES_NOT_FOLLOWED")
			continue
		}
		if spec != "" && !requirementSpec.MatchString(spec) {
			r.Warn("UNSUPPORTED_REQUIREMENT")
			continue
		}
		version := ""
		if strings.HasPrefix(spec, "==") && pyVersion.MatchString(strings.TrimSpace(spec[2:])) {
			version = strings.TrimSpace(spec[2:])
		} else {
			r.Warn("DECLARED_VERSION_NOT_EXACT")
		}
		c, err := NewComponent("pypi", m[1], version, "declared-requirements", nil)
		if err != nil {
			return err
		}
		if err = r.Add(c); err != nil {
			return err
		}
	}
	if s.Err() != nil {
		return errors.New("requirements line exceeds limit")
	}
	return nil
}
