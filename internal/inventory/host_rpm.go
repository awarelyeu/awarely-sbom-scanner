package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

const defaultRPMSelection = "nginx*,httpd*,openssl,openssh-server,nodejs*,python3*,php*,java-*,postgresql*,mysql-server*,mariadb-server*,redis*,docker-ce,containerd.io,runc,podman"

var rpmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,199}$`)
var rpmPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~^]{0,99}$`)
var rpmArch = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,31}$`)
var rpmModule = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*:[A-Za-z0-9][A-Za-z0-9._+-]*:[0-9]+:[A-Za-z0-9_]+$`)

type rpmPackage struct {
	Name, Version, Arch, SourceName, SourceVersion, Vendor, Module string
	Requires, Provides                                             []string
}

func parseRPMHeader(b []byte) (rpmPackage, error) {
	var p rpmPackage
	if len(b) < 8 || len(b) > maxRPMHeader {
		return p, errRPMDB
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	size := int(binary.BigEndian.Uint32(b[4:8]))
	if n < 1 || n > 16384 || 8+n*16 > len(b) || 8+n*16+size != len(b) {
		return p, errRPMDB
	}
	data := b[8+n*16:]
	fields := map[uint32][]string{}
	var epoch uint32
	seen := map[uint32]bool{}
	var dirs, base []string
	var indexes []uint32
	for i := 0; i < n; i++ {
		e := b[8+i*16 : 24+i*16]
		tag := binary.BigEndian.Uint32(e[:4])
		typ := binary.BigEndian.Uint32(e[4:8])
		off := int(binary.BigEndian.Uint32(e[8:12]))
		count := int(binary.BigEndian.Uint32(e[12:]))
		wanted := tag == 1000 || tag == 1001 || tag == 1002 || tag == 1003 || tag == 1011 || tag == 1022 || tag == 1044 || tag == 1047 || tag == 1049 || tag == 5096 || tag == 1116 || tag == 1117 || tag == 1118
		if !wanted {
			continue
		}
		if seen[tag] && tag == 1044 {
			// RPM 4.19 may repeat SOURCERPM in the installed header's
			// mutable region. Accept an identical scalar only; conflicting
			// identities still fail closed instead of picking an arbitrary one.
			if typ != 6 || count != 1 || off >= len(data) {
				return p, errRPMDB
			}
			end := bytes.IndexByte(data[off:], 0)
			if end < 0 || end > 4096 || len(fields[tag]) != 1 || string(data[off:off+end]) != fields[tag][0] {
				return p, errRPMDB
			}
			continue
		}
		if seen[tag] || off < 0 || off >= len(data) || count < 1 || count > 262144 {
			return p, errRPMDB
		}
		seen[tag] = true
		if tag == 1003 || tag == 1116 {
			if typ != 4 || count > (len(data)-off)/4 || (tag == 1003 && count != 1) {
				return p, errRPMDB
			}
			for j := 0; j < count; j++ {
				v := binary.BigEndian.Uint32(data[off+j*4 : off+j*4+4])
				if tag == 1003 {
					epoch = v
				} else {
					indexes = append(indexes, v)
				}
			}
			continue
		}
		array := tag == 1047 || tag == 1049 || tag == 1117 || tag == 1118
		if (array && typ != 8) || (!array && (typ != 6 || count != 1)) {
			return p, errRPMDB
		}
		for j := 0; j < count; j++ {
			if off >= len(data) {
				return p, errRPMDB
			}
			end := bytes.IndexByte(data[off:], 0)
			if end < 0 || end > 4096 {
				return p, errRPMDB
			}
			value := string(data[off : off+end])
			if !ValidText(value, 4096) && !(tag == 1117 && value == "") {
				return p, errRPMDB
			}
			fields[tag] = append(fields[tag], value)
			off += end + 1
		}
	}
	one := func(tag uint32) string {
		if len(fields[tag]) == 1 {
			return fields[tag][0]
		}
		return ""
	}
	p.Name, p.Arch, p.Vendor, p.Module = one(1000), one(1022), one(1011), one(5096)
	version, release := one(1001), one(1002)
	if p.Name == "gpg-pubkey" {
		return p, nil
	}
	if !rpmName.MatchString(p.Name) || !rpmArch.MatchString(p.Arch) || !rpmPart.MatchString(version) || !rpmPart.MatchString(release) || (p.Module != "" && !rpmModule.MatchString(p.Module)) || len(p.Vendor) > 200 {
		return p, errRPMDB
	}
	p.Version = strconv.FormatUint(uint64(epoch), 10) + ":" + version + "-" + release
	if len(p.Version) > 100 {
		return p, errRPMDB
	}
	source := one(1044)
	if strings.HasSuffix(source, ".src.rpm") {
		source = strings.TrimSuffix(source, ".src.rpm")
		i := strings.LastIndexByte(source, '-')
		if i > 0 {
			sr := source[i+1:]
			source = source[:i]
			i = strings.LastIndexByte(source, '-')
			if i > 0 && rpmName.MatchString(source[:i]) && rpmPart.MatchString(source[i+1:]) && rpmPart.MatchString(sr) {
				p.SourceName = source[:i]
				p.SourceVersion = source[i+1:] + "-" + sr
			}
		}
	}
	p.Requires, p.Provides = fields[1049], fields[1047]
	dirs, base = fields[1118], fields[1117]
	if len(base) != len(indexes) {
		return p, errRPMDB
	}
	for i, name := range base {
		if int(indexes[i]) >= len(dirs) {
			return p, errRPMDB
		}
		p.Provides = append(p.Provides, dirs[indexes[i]]+name)
	}
	return p, nil
}

func hostRPM(ctx context.Context, root *os.Root, distro, release, selection string, all bool) (Result, error) {
	r := Result{Scope: "selected installed RPM packages and installed capability providers"}
	if selection == DefaultSelection {
		selection = defaultRPMSelection
	}
	var b []byte
	chosen := ""
	for _, name := range []string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "usr/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"} {
		_, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return r, errRPMDB
		}
		if chosen != "" { // aliases may refer to the same database through a directory symlink
			first, _ := root.Stat(chosen)
			next, _ := root.Stat(name)
			if first == nil || next == nil || !os.SameFile(first, next) {
				return r, errors.New("multiple RPM databases found; select a root with one active database")
			}
			continue
		}
		chosen = name
	}
	if chosen == "" {
		return r, errors.New("no supported RPM database found (SQLite or Berkeley DB hash required)")
	}
	// A database snapshot is accepted only while package management is idle.
	// WAL needs a committed, checksummed overlay; never silently ignore it.
	read := func() ([]byte, []byte, error) {
		for _, suffix := range []string{"-journal"} {
			info, e := root.Lstat(chosen + suffix)
			if e == nil && info.Size() != 0 {
				return nil, nil, errRPMDB
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return nil, nil, errRPMDB
			}
		}
		db, e := safeio.ReadRegular(ctx, root, chosen, 128<<20)
		if e != nil {
			return nil, nil, errRPMDB
		}
		wal, e := safeio.ReadRegular(ctx, root, chosen+"-wal", 64<<20)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
		return db, wal, e
	}
	b, wal, err := read()
	if err != nil {
		return r, errRPMDB
	}
	digest, wdigest := sha256.Sum256(b), sha256.Sum256(wal)
	if len(wal) > 0 {
		b, err = sqliteWAL(ctx, b, wal)
		if err != nil {
			return r, err
		}
	}
	pkgs := map[string]rpmPackage{}
	err = rpmRecords(ctx, b, func(blob []byte) error {
		p, e := parseRPMHeader(blob)
		if e != nil {
			return e
		}
		if p.Name == "gpg-pubkey" {
			return nil
		}
		id := p.Name + "@" + p.Version + ":" + p.Arch
		if _, ok := pkgs[id]; ok {
			return errRPMDB
		}
		pkgs[id] = p
		return nil
	})
	if err != nil {
		return r, err
	}
	b2, w2, e := read()
	if e != nil || sha256.Sum256(b2) != digest || sha256.Sum256(w2) != wdigest {
		return r, errRPMDB
	}
	selectors := strings.Split(selection, ",")
	if all {
		selectors = nil
		r.Scope = "all installed RPM packages; unmanaged software excluded"
	}
	for _, s := range selectors {
		if !rpmName.MatchString(strings.TrimSuffix(s, "*")) {
			return r, errors.New("invalid package selector; use package names or trailing *")
		}
	}
	providers := map[string][]string{}
	selected := map[string]bool{}
	matched := map[string]bool{}
	var queue []string
	for id, p := range pkgs {
		providers[p.Name] = append(providers[p.Name], id)
		for _, cap := range p.Provides {
			providers[cap] = append(providers[cap], id)
		}
		yes := all
		for _, s := range selectors {
			if s == p.Name || (strings.HasSuffix(s, "*") && strings.HasPrefix(p.Name, strings.TrimSuffix(s, "*"))) {
				yes = true
				matched[s] = true
			}
		}
		if yes {
			queue = append(queue, id)
			selected[id] = true
		}
	}
	if len(queue) == 0 {
		r.Warn("NO_SELECTED_PACKAGES_INSTALLED")
	}
	if !all && selection != defaultRPMSelection && len(matched) < len(selectors) {
		r.Warn("EXPLICIT_SELECTOR_WITHOUT_INSTALLED_MATCH")
	}
	for i := 0; i < len(queue); i++ {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		if len(queue) > MaxComponents {
			return r, errors.New("selected dependency closure exceeds component limit")
		}
		if all {
			continue
		}
		p := pkgs[queue[i]]
		for _, cap := range p.Requires {
			resolved := rpmDependency(cap, func(name string) []string {
				var ids []string
				for _, id := range providers[name] {
					candidate := pkgs[id]
					if candidate.Arch == p.Arch || candidate.Arch == "noarch" || p.Arch == "noarch" {
						ids = append(ids, id)
					}
				}
				return ids
			})
			for id := range resolved.ids {
				if !selected[id] {
					selected[id] = true
					queue = append(queue, id)
				}
			}
			if !resolved.covered {
				r.Warn("DEPENDENCY_PROVIDER_NOT_FOUND")
			}
		}
	}
	sort.Strings(queue)
	for _, id := range queue {
		p := pkgs[id]
		q := url.Values{"arch": {p.Arch}, "distro": {distro + "-" + release}}
		c, e := NewComponent("rpm", p.Name, p.Version, "installed-rpm", q)
		if e != nil {
			return r, e
		}
		if p.SourceName != "" {
			c.Properties = append(c.Properties, Property{"awarely:source-package", p.SourceName}, Property{"awarely:source-version", p.SourceVersion})
		}
		if p.Vendor != "" {
			c.Properties = append(c.Properties, Property{"awarely:rpm-vendor", p.Vendor})
		}
		if p.Module != "" {
			c.Properties = append(c.Properties, Property{"awarely:rpm-module", p.Module})
		}
		if e = r.Add(c); e != nil {
			return r, e
		}
	}
	r.Inputs = []string{"os-release", "rpm-database"}
	if !all {
		r.Scope += "; selectors=" + selection
	}
	return r, ctx.Err()
}
