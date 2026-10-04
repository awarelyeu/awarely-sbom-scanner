// Package guided orchestrates explicit user choices. It never discovers API
// credentials, silently installs tools or sends a local inventory by default.
package guided

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awarelyeu/awarely-sbom-scanner/internal/api"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/inventory"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/producer"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/safeio"
)

type session struct {
	ctx         context.Context
	reader      *bufio.Scanner
	out, errOut io.Writer
	version     string
	remote      func(context.Context, api.Credentials, api.Snapshot, string) ([]byte, error)
}

func Run(ctx context.Context, input io.Reader, out, errOut io.Writer, version string) int {
	s := &session{ctx: ctx, reader: bufio.NewScanner(input), out: out, errOut: errOut, version: version}
	s.reader.Buffer(make([]byte, 4096), 4096)
	s.remote = func(ctx context.Context, credentials api.Credentials, snapshot api.Snapshot, action string) ([]byte, error) {
		client := api.NewClient(credentials)
		if action == "check" {
			return client.Check(ctx, snapshot)
		}
		return client.Sync(ctx, snapshot, "", "", false)
	}
	return s.run()
}

var cancelled = errors.New("cancelled; any completed local export was preserved")

func (s *session) ask(label, fallback string) (string, error) {
	if s.ctx.Err() != nil {
		return "", cancelled
	}
	fmt.Fprint(s.out, label)
	if fallback != "" {
		fmt.Fprintf(s.out, " [%s]", fallback)
	}
	fmt.Fprint(s.out, ": ")
	ready := make(chan bool, 1)
	go func() { ready <- s.reader.Scan() }()
	select {
	case ok := <-ready:
		if !ok {
			return "", cancelled
		}
	case <-s.ctx.Done():
		return "", cancelled
	}
	value := strings.TrimSpace(s.reader.Text())
	if value == "q" || value == "quit" || s.ctx.Err() != nil {
		return "", cancelled
	}
	if value == "" {
		value = fallback
	}
	if value != "" && !inventory.ValidText(value, 4095) {
		return "", errors.New("input contains unsupported characters")
	}
	return value, nil
}
func (s *session) choice(label, fallback string, choices ...string) (string, error) {
	for {
		v, e := s.ask(label, fallback)
		if e != nil {
			return "", e
		}
		for _, option := range choices {
			if v == option {
				return v, nil
			}
		}
		fmt.Fprintln(s.out, "Choose one of:", strings.Join(choices, ", "), "(or q to quit).")
	}
}
func (s *session) confirm(label string) (bool, error) {
	v, e := s.choice(label+" (yes/no)", "no", "yes", "no")
	return v == "yes", e
}
func (s *session) fail(err error) int {
	fmt.Fprintln(s.errOut, "STOP:", err)
	if errors.Is(err, cancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || s.ctx.Err() != nil {
		return 5
	}
	return 2
}
func selectedPath(raw string) (string, error) {
	if raw == "~" || strings.HasPrefix(raw, "~/") {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", errors.New("home directory is unavailable")
		}
		raw = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(raw, "~"), "/"))
	}
	if raw == "" {
		return "", errors.New("provide a path, without shell commands or quotes")
	}
	p, e := filepath.Abs(raw)
	if e != nil {
		return "", errors.New("invalid path")
	}
	return p, nil
}

func (s *session) run() int {
	fmt.Fprintln(s.out, "Awarely Scan - guided setup\nChoose a scan. Nothing is uploaded by default. Type q to quit.\n\n1. Linux host - focused installed packages\n2. npm / Node.js application\n3. Python application\n4. Java application (Syft)\n5. Other application ecosystems (Syft)")
	mode, err := s.choice("Scan type", "", "1", "2", "3", "4", "5")
	if err != nil {
		return s.fail(err)
	}
	kind := map[string]string{"1": "linux", "2": "npm", "3": "python", "4": "java", "5": "other"}[mode]
	var target string
	all, syft := false, kind == "java" || kind == "other"
	if kind == "linux" {
		fmt.Fprintln(s.out, "The distribution is detected automatically. No package manager or root access is needed.\n1. Focused server packages and installed dependencies (recommended)\n2. All installed packages (larger inventory; account limits still apply)")
		profile, e := s.choice("Linux scope", "1", "1", "2")
		if e != nil {
			return s.fail(e)
		}
		all = profile == "2"
	} else {
		fmt.Fprintln(s.out, "Enter the application directory as a path, not a command. Examples: /srv/demo-shop, /srv/demo-python, /srv/demo-java.")
		p, e := s.ask("Application directory", "")
		if e != nil {
			return s.fail(e)
		}
		target, e = selectedPath(p)
		if e != nil {
			return s.fail(e)
		}
		info, e := os.Stat(target)
		if e != nil || !info.IsDir() {
			return s.fail(errors.New("application directory is missing or unreadable; choose an existing directory"))
		}
		if kind == "npm" {
			fmt.Fprintln(s.out, "1. Read npm lockfile (recommended; no Node.js/npm installation needed)\n2. Inspect application files with Syft (optional download)")
			v, e := s.choice("npm collection", "1", "1", "2")
			if e != nil {
				return s.fail(e)
			}
			syft = v == "2"
		}
		if kind == "python" {
			fmt.Fprintln(s.out, "1. Read requirements.txt (no Python installation needed; partial inventory)\n2. Inspect an existing virtual environment with Syft (includes installed dependencies)")
			v, e := s.choice("Python collection", "1", "1", "2")
			if e != nil {
				return s.fail(e)
			}
			syft = v == "2"
		}
	}
	var result inventory.Result
	if syft {
		if !producer.Supported() {
			return s.fail(errors.New("managed Syft supports Linux amd64/arm64; use import for an externally generated SBOM"))
		}
		if err := preflight(s.ctx, target, kind, syft); err != nil {
			return s.fail(err)
		}
		if kind == "other" {
			fmt.Fprintln(s.out, "NuGet, Go, Composer, RubyGems and Cargo can be inventoried/synced. Their CVE assessment is currently unevaluated.")
		}
		cache, e := producer.CachePath()
		if e != nil {
			return s.fail(e)
		}
		ready, e := producer.Cached(s.ctx, cache)
		if e != nil {
			return s.fail(e)
		}
		fmt.Fprintf(s.out, "Syft %s will inspect only the selected application directory.\nIt will not build the project or install its dependencies.\n", producer.Version)
		if !ready {
			fmt.Fprintln(s.out, "Syft is missing from the verified cache. Awarely can download about 30 MB from GitHub, verify the pinned SHA-256 and run it without root. No GitHub account, gh or Cosign is needed.")
		}
		fmt.Fprintln(s.out, "Third-party parsing uses a fixed offline configuration and an environment without your credentials. This is not an OS sandbox; scan only authorized inputs.")
		approved, e := s.confirm("Prepare and run verified Syft")
		if e != nil {
			return s.fail(e)
		}
		if !approved {
			fmt.Fprintln(s.out, "Cancelled. No tool was downloaded and no scan was run.")
			return 0
		}
		if err := producer.Prepare(s.ctx, cache, !ready); err != nil {
			return s.fail(err)
		}
		fmt.Fprintln(s.out, "Scanning with verified Syft...")
		result, err = producer.Scan(s.ctx, cache, target, kind)
	} else {
		if kind != "linux" {
			if err := preflight(s.ctx, target, kind, syft); err != nil {
				return s.fail(err)
			}
		}
		fmt.Fprintln(s.out, "Scanning selected inputs locally...")
		ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
		if kind == "linux" {
			result, err = inventory.Host(ctx, "/", inventory.DefaultSelection, all)
		} else {
			result, err = inventory.AppFor(ctx, target, kind)
		}
		cancel()
	}
	if err != nil {
		return s.fail(err)
	}
	fmt.Fprintf(s.out, "Found %d unique components. No inventory was sent.\n", len(result.Components))
	for _, n := range result.Notices {
		fmt.Fprintln(s.out, "Notice:", n)
	}
	for _, w := range result.Warnings {
		fmt.Fprintln(s.out, "Coverage warning:", w)
	}
	if len(result.Warnings) > 0 {
		fmt.Fprintln(s.out, "This is a partial inventory. Local export and API check are available; synchronization is disabled.")
	}
	if !syft && kind == "python" {
		fmt.Fprintln(s.out, "requirements.txt lists declarations, not a complete installed environment. Choose Python > 2 next time to inspect an existing virtual environment with Syft.")
	}
	if !syft && kind == "npm" && len(result.Warnings) > 0 {
		fmt.Fprintln(s.out, "Prefer package-lock.json or npm-shrinkwrap.json v2/v3 from a trusted build. Awarely does not run npm install or project scripts. Ranges/workspaces may remain partial.")
	}
	fmt.Fprintln(s.out, "Coverage is limited to selected inputs. This is not yet a vulnerability check.")
	label := "application"
	if kind == "linux" {
		label = "linux-host"
	}
	name, e := s.ask("Application label", label)
	if e != nil {
		return s.fail(e)
	}
	if !inventory.ValidText(name, 120) {
		return s.fail(errors.New("application label must be 1-120 bytes without control characters"))
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return s.fail(errors.New("home directory unavailable"))
	}
	fmt.Fprintln(s.out, "A new private folder will hold the SBOM and any API report; existing files are never overwritten.")
	base, e := s.ask("Parent directory for results", home)
	if e != nil {
		return s.fail(e)
	}
	base, e = selectedPath(base)
	if e != nil {
		return s.fail(e)
	}
	dir, e := os.MkdirTemp(base, "awarely-results-")
	if e != nil {
		return s.fail(errors.New("cannot create results folder; choose a writable existing parent directory"))
	}
	blob, e := inventory.Marshal(result, name, s.version, time.Now())
	if e != nil {
		os.Remove(dir)
		return s.fail(e)
	}
	path := filepath.Join(dir, "inventory.cdx.json")
	if e = safeio.WriteNew(path, blob); e != nil {
		os.Remove(dir)
		return s.fail(e)
	}
	fmt.Fprintf(s.out, "Saved local SBOM: %q\n", path)
	return s.afterExport(path, dir, len(result.Warnings) > 0)
}

func (s *session) afterExport(path, dir string, partial bool) int {
	localCode := 0
	if partial {
		localCode = 3
	}
	fmt.Fprintln(s.out, "\n1. Keep local file / upload it manually in Settings > Assets\n2. Check CVEs through the API (does not save inventory or send alerts)")
	choices := []string{"1", "2"}
	if !partial {
		fmt.Fprintln(s.out, "3. Synchronize inventory through the API (replaces one configured source)")
		choices = append(choices, "3")
	}
	answer, e := s.choice("Next action", "1", choices...)
	if e != nil {
		return s.fail(e)
	}
	if answer == "1" {
		fmt.Fprintf(s.out, "Done. Your local SBOM is %q\nFor manual upload: Settings > Assets > Import, review the changes, then Save.\n", path)
		return localCode
	}
	action := "check"
	if answer == "3" {
		action = "sync"
	}
	fmt.Fprintln(s.out, "In Awarely Monitor: Settings > Assets > Awarely Scan CLI.\nWith Pro access and MFA, create a credential for the intended application/source.\nUse Check only for checks, or Sync only / Check and sync for synchronization.\nDownload the credential JSON, transfer it securely to this machine outside the project, and run: chmod 600 /path/to/awarely-credentials.json\nEnter its file path below. Never paste the token into this prompt.")
	raw, e := s.ask("Credential JSON file (q to finish with the local file)", "")
	if e != nil {
		return s.fail(e)
	}
	credentialPath, e := selectedPath(raw)
	if e != nil {
		return s.fail(e)
	}
	credentials, e := api.ReadCredentials(s.ctx, credentialPath, strings.NewReader(""))
	if e != nil {
		return s.fail(e)
	}
	snapshot, e := api.ReadSnapshot(s.ctx, path)
	if e != nil {
		return s.fail(e)
	}
	snapshot.CollectorVersion = s.version
	fmt.Fprintf(s.out, "Destination: %q\nApplication ID: %s\nSource ID: %s\nComponents: %d\n", credentials.APIURL, credentials.ApplicationID, credentials.SourceID, len(snapshot.Components))
	fmt.Fprintln(s.out, "Only normalized package identities, versions and evidence are sent; credentials authenticate the request.")
	if action == "sync" {
		fmt.Fprintln(s.out, "SYNC replaces this source immediately. Other sources are preserved. Future alerts follow saved preferences; this does not send retrospective emails.")
	} else {
		fmt.Fprintln(s.out, "CHECK returns a local report. Saved inventory and alert settings remain unchanged.")
	}
	approved, e := s.confirm("Send inventory for " + action)
	if e != nil {
		return s.fail(e)
	}
	if !approved {
		fmt.Fprintln(s.out, "No API request was sent. Your local SBOM is ready.")
		return localCode
	}
	ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
	defer cancel()
	report, e := s.remote(ctx, credentials, snapshot, action)
	if e != nil {
		fmt.Fprintln(s.errOut, "API operation failed:", e, "Your local SBOM was preserved.")
		return 6
	}
	reportPath := filepath.Join(dir, action+"-result.json")
	if e := safeio.WriteNew(reportPath, append(report, '\n')); e != nil {
		fmt.Fprintln(s.errOut, "API completed but the report could not be saved; a sync may already be committed.")
		return 4
	}
	fmt.Fprintf(s.out, "Saved complete %s report: %q\n", action, reportPath)
	if action == "check" {
		printSummary(s.out, report)
	} else {
		fmt.Fprintln(s.out, "Source synchronized. View the saved inventory in Settings > Assets.")
	}
	return localCode
}

func printSummary(out io.Writer, report []byte) {
	var r struct {
		Summary struct {
			CVEs       int `json:"matchedCves"`
			Components int `json:"componentMatches"`
		} `json:"summary"`
		Coverage struct {
			Unevaluated []json.RawMessage `json:"unevaluated"`
		} `json:"coverage"`
	}
	if json.Unmarshal(report, &r) == nil {
		fmt.Fprintf(out, "Matched CVEs: %d | Component matches: %d | Unevaluated: %d\n", r.Summary.CVEs, r.Summary.Components, len(r.Coverage.Unevaluated))
	}
	fmt.Fprintln(out, "Review the full report for versions, precision, fixes and coverage. No matches does not mean the application is secure.")
}

func preflight(ctx context.Context, path, kind string, syft bool) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == "/" {
		return errors.New("select a readable application directory, not the host root")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if kind == "npm" && !syft {
		for _, n := range []string{"npm-shrinkwrap.json", "package-lock.json", "package.json"} {
			if _, e := os.Lstat(filepath.Join(path, n)); e == nil {
				return nil
			}
		}
		return errors.New("no npm manifest found; select the project root containing package-lock.json (v2/v3), npm-shrinkwrap.json or package.json; Node.js/npm is not needed by the scanner")
	}
	if kind == "python" && !syft {
		if _, e := os.Lstat(filepath.Join(path, "requirements.txt")); e == nil {
			return nil
		}
		return errors.New("requirements.txt is missing; choose the project root or Python > 2 for an existing virtual environment")
	}
	count := 0
	found := false
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count++
		if count > 50000 {
			return errors.New("too many entries")
		}
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".awarely-scan-tools") {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Type().IsRegular() {
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if kind == "java" {
				found = ext == ".jar" || ext == ".war" || ext == ".ear"
			} else if kind == "python" {
				found = (d.Name() == "METADATA" && strings.HasSuffix(filepath.Base(filepath.Dir(p)), ".dist-info")) || d.Name() == "PKG-INFO"
			} else {
				found = true
			}
			if found {
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return errors.New("cannot inspect selected files; check permissions or choose a smaller directory")
	}
	if found {
		return nil
	}
	if kind == "java" {
		return errors.New("no JAR/WAR/EAR found; provide artifacts from your trusted Maven/Gradle build in this directory. Awarely does not install Java or build/run your project")
	}
	if kind == "python" {
		return errors.New("no installed Python metadata found; select a directory containing an existing virtual environment. Awarely does not install Python or packages; use Python > 1 for requirements.txt")
	}
	return errors.New("no application files found; choose a project or build output directory")
}
