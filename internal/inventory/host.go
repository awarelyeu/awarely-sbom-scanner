package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

const DefaultSelection = "nginx*,apache2*,openssl,openssh-server,nodejs,python3,php*,openjdk-*,postgresql*,mysql-server*,mariadb-server*,redis-server,docker.io,containerd,runc"

var distroValue = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var archValue = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type debPackage struct{ Name, Version, Arch, Depends, Provides string }

func Host(ctx context.Context, path, selection string, all bool) (Result, error) {
	r := Result{Scope: "selected installed DEB packages and Depends/Pre-Depends closure"}
	root, err := os.OpenRoot(path)
	if err != nil {
		return r, errors.New("cannot open selected Linux root")
	}
	defer root.Close()
	b, err := safeio.ReadRegular(ctx, root, "etc/os-release", 64<<10)
	if err != nil {
		b, err = safeio.ReadRegular(ctx, root, "usr/lib/os-release", 64<<10)
	}
	if err != nil {
		return r, errors.New("cannot safely read Linux distribution metadata")
	}
	distro, release, err := parseOSRelease(b)
	if err != nil {
		return r, err
	}
	b, err = safeio.ReadRegular(ctx, root, "var/lib/dpkg/status", 64<<20)
	if err != nil {
		return r, errors.New("cannot safely read dpkg status; only Debian/Ubuntu roots are supported")
	}
	pkgs, err := parseDPKG(ctx, b)
	if err != nil {
		return r, err
	}
	selectors := strings.Split(selection, ",")
	if all {
		selectors = nil
		r.Scope = "all installed DEB packages; unmanaged software excluded"
	}
	for _, s := range selectors {
		if !debName.MatchString(strings.TrimSuffix(s, "*")) {
			return r, errors.New("invalid package selector; use package names or trailing *")
		}
	}
	byName := map[string][]string{}
	providers := map[string][]string{}
	for id, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], id)
		for _, name := range dependencyNames(p.Provides) {
			providers[name] = append(providers[name], id)
		}
	}
	selected := map[string]bool{}
	matchedSelectors := map[string]bool{}
	queue := []string{}
	for id, p := range pkgs {
		match := all
		for _, s := range selectors {
			if s == p.Name || (strings.HasSuffix(s, "*") && strings.HasPrefix(p.Name, strings.TrimSuffix(s, "*"))) {
				match = true
				matchedSelectors[s] = true
			}
		}
		if match {
			selected[id] = true
			queue = append(queue, id)
		}
	}
	if len(queue) == 0 {
		r.Warn("NO_SELECTED_PACKAGES_INSTALLED")
	}
	if !all && selection != DefaultSelection && len(matchedSelectors) < len(selectors) {
		for _, s := range selectors {
			if !matchedSelectors[s] {
				r.Warn("EXPLICIT_SELECTOR_WITHOUT_INSTALLED_MATCH")
			}
		}
	}
	for i := 0; i < len(queue); i++ {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if len(queue) > MaxComponents {
			return r, errors.New("selected dependency closure exceeds component limit")
		}
		p := pkgs[queue[i]]
		for _, group := range strings.Split(p.Depends, ",") {
			if err := ctx.Err(); err != nil {
				return r, err
			}
			if strings.TrimSpace(group) == "" {
				continue
			}
			resolved := false
			for _, name := range dependencyNames(group) {
				ids := append(append([]string{}, byName[name]...), providers[name]...)
				for _, id := range ids {
					resolved = true
					if !selected[id] {
						selected[id] = true
						queue = append(queue, id)
					}
				}
			}
			if !resolved {
				r.Warn("DEPENDENCY_PROVIDER_NOT_FOUND")
			}
		}
	}
	sort.Strings(queue)
	for _, id := range queue {
		p := pkgs[id]
		q := url.Values{"arch": {p.Arch}, "distro": {distro + "-" + release}}
		c, err := NewComponent("deb", p.Name, p.Version, "installed-dpkg", q)
		if err != nil {
			return r, err
		}
		if err = r.Add(c); err != nil {
			return r, err
		}
	}
	r.Inputs = []string{"os-release", "dpkg-status"}
	if !all {
		r.Scope += "; selectors=" + selection
	}
	return r, ctx.Err()
}

func parseOSRelease(b []byte) (string, string, error) {
	if !utf8.Valid(b) {
		return "", "", errors.New("invalid distribution metadata")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || (k != "ID" && k != "VERSION_ID") {
			continue
		}
		if _, dup := fields[k]; dup {
			return "", "", errors.New("duplicate distribution field")
		}
		v = strings.Trim(v, "\"'")
		if !distroValue.MatchString(v) {
			return "", "", errors.New("invalid distribution value")
		}
		fields[k] = v
	}
	if (fields["ID"] != "debian" && fields["ID"] != "ubuntu") || fields["VERSION_ID"] == "" {
		return "", "", errors.New("only versioned Debian/Ubuntu distributions are supported")
	}
	return fields["ID"], fields["VERSION_ID"], nil
}

func dependencyNames(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == '|' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := strings.Fields(part)[0]
		name = strings.SplitN(name, ":", 2)[0]
		if debName.MatchString(name) {
			out = append(out, name)
		}
	}
	return out
}

func parseDPKG(ctx context.Context, b []byte) (map[string]debPackage, error) {
	if len(b) > 64<<20 || !utf8.Valid(b) {
		return nil, errors.New("invalid or oversized dpkg status")
	}
	pkgs := map[string]debPackage{}
	fields := map[string]string{}
	last := ""
	records := 0
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		records++
		if records > 50000 {
			return errors.New("too many dpkg records")
		}
		if fields["Status"] == "install ok installed" || fields["Status"] == "hold ok installed" {
			p := debPackage{fields["Package"], fields["Version"], fields["Architecture"], fields["Depends"] + "," + fields["Pre-Depends"], fields["Provides"]}
			if !debName.MatchString(p.Name) || !ValidText(p.Name, 200) || !versionText.MatchString(p.Version) || !ValidText(p.Version, 100) || !archValue.MatchString(p.Arch) {
				return errors.New("invalid installed package identity")
			}
			id := p.Name + ":" + p.Arch
			if _, dup := pkgs[id]; dup {
				return errors.New("duplicate installed package record")
			}
			pkgs[id] = p
		}
		fields = map[string]string{}
		last = ""
		return nil
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 4096), 64<<10)
	for s.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := s.Text()
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				fields[last] += " " + strings.TrimSpace(line)
				if len(fields[last]) > 64<<10 {
					return nil, errors.New("dpkg field too long")
				}
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("malformed dpkg record")
		}
		last = ""
		switch k {
		case "Package", "Version", "Architecture", "Status", "Depends", "Pre-Depends", "Provides":
			if _, dup := fields[k]; dup {
				return nil, errors.New("duplicate dpkg field")
			}
			fields[k] = strings.TrimSpace(v)
			last = k
		}
	}
	if s.Err() != nil {
		return nil, errors.New("dpkg line exceeds limit")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return pkgs, nil
}
