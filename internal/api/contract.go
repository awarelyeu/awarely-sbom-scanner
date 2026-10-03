// Package api implements explicit, authenticated remote operations. The local
// collector remains independent of this package and never discovers credentials.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Component struct {
	Ecosystem           string `json:"ecosystem"`
	Name                string `json:"name"`
	Version             string `json:"version"`
	Evidence            string `json:"evidence"`
	Distribution        string `json:"distribution,omitempty"`
	DistributionVersion string `json:"distributionVersion,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
	SourcePackage       string `json:"sourcePackage,omitempty"`
	SourceVersion       string `json:"sourceVersion,omitempty"`
	RPMVendor           string `json:"rpmVendor,omitempty"`
	RPMModule           string `json:"rpmModule,omitempty"`
}
type Snapshot struct {
	SchemaVersion    int         `json:"schemaVersion"`
	CollectorVersion string      `json:"collectorVersion"`
	Coverage         string      `json:"coverage"`
	Components       []Component `json:"components"`
}

func ReadSnapshot(ctx context.Context, path string) (Snapshot, error) {
	var snapshot Snapshot
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return snapshot, errors.New("cannot open SBOM directory")
	}
	defer root.Close()
	b, err := safeio.ReadRegular(ctx, root, filepath.Base(path), inventory.MaxManifestBytes)
	if err != nil {
		return snapshot, errors.New("cannot safely read SBOM")
	}
	if err := inventory.ValidateJSON(ctx, b); err != nil {
		return snapshot, err
	}
	var bom struct {
		Format   string `json:"bomFormat"`
		Spec     string `json:"specVersion"`
		Metadata struct {
			Properties []inventory.Property `json:"properties"`
		} `json:"metadata"`
		Components []inventory.Component `json:"components"`
	}
	if json.Unmarshal(b, &bom) != nil || bom.Format != "CycloneDX" || bom.Spec != "1.6" || len(bom.Components) > inventory.MaxComponents {
		return snapshot, errors.New("expected bounded CycloneDX 1.6 inventory")
	}
	coverage := "partial"
	coverageFound := false
	for _, p := range bom.Metadata.Properties {
		if p.Name == "awarely:coverage" {
			if coverageFound {
				return snapshot, errors.New("ambiguous coverage metadata")
			}
			coverageFound = true
			if p.Value == "complete-for-selected-inputs" {
				coverage = "complete"
			}
		}
	}
	snapshot = Snapshot{SchemaVersion: 1, Coverage: coverage, Components: []Component{}}
	seen := map[string]bool{}
	for _, c := range bom.Components {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		if !strings.HasPrefix(c.PURL, "pkg:") || strings.Contains(c.PURL, "#") {
			return Snapshot{}, errors.New("component needs a supported package URL")
		}
		body, rawQuery, _ := strings.Cut(strings.TrimPrefix(c.PURL, "pkg:"), "?")
		ecosystem, identity, ok := strings.Cut(body, "/")
		if !ok {
			return Snapshot{}, errors.New("invalid package URL")
		}
		at := strings.LastIndex(identity, "@")
		version := ""
		if at > 0 {
			version, err = url.PathUnescape(identity[at+1:])
			if err != nil {
				return Snapshot{}, errors.New("invalid package version")
			}
			identity = identity[:at]
		}
		name, err := url.PathUnescape(identity)
		if err != nil {
			return Snapshot{}, errors.New("invalid package identity")
		}
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return Snapshot{}, errors.New("invalid package qualifiers")
		}
		out := Component{Ecosystem: ecosystem, Name: name, Version: version}
		if ecosystem == "deb" || ecosystem == "rpm" {
			distro, packageName, valid := strings.Cut(name, "/")
			if !valid || ((ecosystem == "deb" && distro != "debian" && distro != "ubuntu") || (ecosystem == "rpm" && distro != "rocky" && distro != "almalinux")) {
				return Snapshot{}, errors.New("unsupported distribution")
			}
			out.Name, out.Distribution, out.Architecture = packageName, distro, q.Get("arch")
			if !strings.HasPrefix(q.Get("distro"), distro+"-") {
				return Snapshot{}, errors.New("distribution qualifier required")
			}
			out.DistributionVersion = strings.TrimPrefix(q.Get("distro"), distro+"-")
			if len(q) != 2 || len(q["arch"]) != 1 || len(q["distro"]) != 1 || out.DistributionVersion == "" || out.Architecture == "" {
				return Snapshot{}, errors.New("invalid distribution qualifiers")
			}
		} else if (ecosystem != "npm" && ecosystem != "pypi") || len(q) != 0 {
			return Snapshot{}, errors.New("unsupported package identity")
		}
		if c.Name != out.Name || c.Version != version {
			return Snapshot{}, errors.New("SBOM name/version disagrees with package URL")
		}
		sourceSeen := map[string]bool{}
		for _, p := range c.Properties {
			if p.Name == "awarely:source-package" || p.Name == "awarely:source-version" {
				if (ecosystem != "deb" && ecosystem != "rpm") || sourceSeen[p.Name] || p.Value == "" {
					return Snapshot{}, errors.New("invalid source package metadata")
				}
				sourceSeen[p.Name] = true
				if p.Name == "awarely:source-package" {
					out.SourcePackage = p.Value
				} else {
					out.SourceVersion = p.Value
				}
			}
			if p.Name == "awarely:rpm-vendor" || p.Name == "awarely:rpm-module" {
				if ecosystem != "rpm" || sourceSeen[p.Name] || !inventory.ValidText(p.Value, 200) {
					return Snapshot{}, errors.New("invalid RPM metadata")
				}
				sourceSeen[p.Name] = true
				if p.Name == "awarely:rpm-vendor" {
					out.RPMVendor = p.Value
				} else {
					out.RPMModule = p.Value
				}
			}
			if p.Name == "awarely:evidence" {
				if out.Evidence != "" {
					return Snapshot{}, errors.New("ambiguous component evidence")
				}
				out.Evidence = p.Value
			}
		}
		if out.SourcePackage != "" || out.SourceVersion != "" {
			if out.SourcePackage == "" || out.SourceVersion == "" {
				return Snapshot{}, errors.New("incomplete source package metadata")
			}
			if _, err := inventory.NewComponent(ecosystem, out.SourcePackage, out.SourceVersion, "installed-dpkg", nil); err != nil {
				return Snapshot{}, err
			}
		}
		if out.Evidence != "resolved-lockfile" && out.Evidence != "declared-manifest" && out.Evidence != "declared-requirements" && out.Evidence != "installed-dpkg" && out.Evidence != "installed-rpm" {
			return Snapshot{}, errors.New("component evidence is missing or unsupported")
		}
		if _, err := inventory.NewComponent(ecosystem, out.Name, out.Version, out.Evidence, nil); err != nil {
			return Snapshot{}, err
		}
		if out.Version == "" || strings.HasPrefix(out.Evidence, "declared-") {
			snapshot.Coverage = "partial"
		}
		if seen[c.PURL] {
			return Snapshot{}, errors.New("duplicate package identity")
		}
		seen[c.PURL] = true
		snapshot.Components = append(snapshot.Components, out)
	}
	return snapshot, nil
}
